"""SOC Master (control plane): registri cluster, kebijakan bertanda tangan, kesehatan armada. BUKAN jalur event, BUKAN worker analisis."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
from collections import Counter
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from services.common.util import utcnow
from services.master import db, poller
from services.master.policy import sign, sign_payload, validate_policy
from services.master.configuration import (
    BOOTSTRAP_KEYS,
    CATALOG as CONFIG_CATALOG,
    SECRET_KEYS,
    config_catalog,
    decrypt_config,
    encrypt_config,
    public_config,
    validate_config,
)

INTERVAL = int(os.getenv("MASTER_POLL_SECONDS", "30"))


def _key() -> str:
    f = os.getenv("MASTER_SIGNING_KEY_FILE", "")
    if f and Path(f).exists():
        return Path(f).read_text().strip()
    k = os.getenv("MASTER_SIGNING_KEY", "")
    if not k:
        raise HTTPException(503, "kunci penandatangan Master belum dikonfigurasi (MASTER_SIGNING_KEY_FILE)")
    return k


def _tokens() -> dict[str, str]:
    out = {}
    from services.common.config import read_secret
    for part in filter(None, read_secret("MASTER_API_TOKENS").split(",")):
        tok, _, role = part.partition(":")
        if role in ("admin", "viewer"):
            out[tok] = role
    return out


def principal(authorization: str = Header(default="")) -> tuple[str, str]:
    t = authorization.removeprefix("Bearer ").strip()
    for k, role in _tokens().items():
        if t and hmac.compare_digest(t, k):
            return f"{role}:{hashlib.sha256(k.encode()).hexdigest()[:6]}", role
    raise HTTPException(401, "token tidak valid")


def need_admin(p=Depends(principal)):
    if p[1] != "admin":
        raise HTTPException(403, "butuh admin")
    return p


def audit(s: Session, actor: str, action: str, target: str = "", detail: dict | None = None):
    s.add(db.MAudit(actor=actor, action=action, target=target, detail=detail or {}))


class ClusterIn(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,40}$")
    name: str; api_url: str = Field(pattern=r"^https?://"); region: str = ""
    status_token_env: str = Field("", pattern=r"^[A-Z0-9_]{0,64}$"); verify_tls: bool = True


class PolicyIn(BaseModel):
    policy: dict
    targets: list[str] = Field(min_length=1)
    note: str = ""


class ClusterConfigurationIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    settings: dict = Field(default_factory=dict)
    secrets: dict[str, str] = Field(default_factory=dict)
    clear_secrets: list[str] = Field(default_factory=list)
    autoscaling: dict = Field(default_factory=dict)
    connectors: list[dict] = Field(default_factory=list)


def effective(s: Session, cluster_id: str) -> db.PolicyRow | None:
    for row in s.scalars(select(db.PolicyRow).order_by(db.PolicyRow.version.desc())):
        if "*" in row.targets or cluster_id in row.targets:
            return row
    return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    stop = threading.Event()
    if os.getenv("MASTER_EMBEDDED_POLLER", "true").lower() == "true":
        threading.Thread(target=poller.loop, args=(stop, INTERVAL), daemon=True, name="master-poller").start()
    yield
    stop.set()


app = FastAPI(title="SOC Master (control plane)", version="1.0.0", lifespan=lifespan)


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "role": "master"}


@app.get("/api/v1/auth/config")
def auth_config():
    return {"mode": "master"}


@app.get("/api/v1/me")
def me(p=Depends(principal)):
    return {"name": p[0], "role": p[1], "tenant_id": "*", "control_plane": "master"}


# ---------------- registri cluster
@app.post("/api/v1/clusters", status_code=201)
def register(body: ClusterIn, p=Depends(need_admin), s: Session = Depends(db.dep)):
    if s.get(db.Cluster, body.id):
        raise HTTPException(409, "cluster sudah terdaftar")
    token = secrets.token_urlsafe(32)
    s.add(db.Cluster(id=body.id, name=body.name, region=body.region, api_url=body.api_url, status_token_env=body.status_token_env, verify_tls=body.verify_tls,
                     pull_token_hash=hashlib.sha256(token.encode()).hexdigest()))
    audit(s, p[0], "cluster.register", body.id)
    s.commit()
    return {"id": body.id, "pull_token": token, "note": "Token tarik-kebijakan ditampilkan SEKALI. Set di cluster: CLUSTER_ID + MASTER_CLUSTER_TOKEN."}


def _fleet(s: Session) -> list[dict]:
    now = utcnow()
    rows = []
    for cl in s.scalars(select(db.Cluster).order_by(db.Cluster.id)):
        st = s.get(db.StatusRow, cl.id)
        target = effective(s, cl.id)
        applied = ((st.status or {}).get("policy") or {}).get("version", 0) if st else 0
        h = poller.classify(st.status if st else None, st.polled_at if st else None, st.ok_at if st else None, now, INTERVAL, target.version if target else 0)
        rows.append({"id": cl.id, "name": cl.name, "region": cl.region, "api_url": cl.api_url, "health": h,
                     "app_version": (st.status or {}).get("version") if st else None, "scoring_version": (st.status or {}).get("scoring_version") if st else None,
                     "policy": {"target": target.version if target else 0, "applied": applied, "in_sync": (not target) or applied >= target.version},
                     "last_ok": st.ok_at.isoformat() if st and st.ok_at else None, "last_error": st.error if st else None,
                     "metrics": {k: (st.status or {}).get(k) for k in ("events_last_hour", "outbox_pending", "outbox_failed", "analysis_pending", "queue", "connectors", "kb")} if st else {}})
        config = s.get(db.ClusterConfiguration, cl.id)
        rows[-1]["configuration"] = {
            "target": config.version if config else 0,
            "applied": ((st.status or {}).get("runtime_config") or {}).get("version", 0) if st else 0,
            "in_sync": (config.version if config else 0) <= (((st.status or {}).get("runtime_config") or {}).get("version", 0) if st else 0),
        }
    return rows


@app.get("/api/v1/clusters")
def clusters(p=Depends(principal), s: Session = Depends(db.dep)):
    return _fleet(s)


@app.get("/api/v1/fleet/summary")
def fleet(p=Depends(principal), s: Session = Depends(db.dep)):
    f = _fleet(s)
    versions = Counter(c["app_version"] or "?" for c in f)
    major = versions.most_common(1)[0][0] if versions else None
    return {"clusters": len(f), "by_state": dict(Counter(c["health"]["state"] for c in f)), "app_versions": dict(versions),
            "version_drift": [c["id"] for c in f if c["app_version"] and c["app_version"] != major],
            "policy_out_of_sync": [c["id"] for c in f if not c["policy"]["in_sync"]]}


@app.post("/api/v1/poll")
def poll_now(p=Depends(need_admin)):
    return {"reachable": poller.poll_all()}


@app.get("/api/v1/config/catalog")
def configuration_catalog(p=Depends(need_admin)):
    return {"settings": config_catalog(), "bootstrap_keys": sorted(BOOTSTRAP_KEYS),
            "autoscaling": [
                {"key": "enabled", "label": "Autoscaling aktif", "kind": "boolean", "default": False},
                {"key": "engine_min", "label": "Worker minimum", "kind": "number", "default": 2, "minimum": 1, "maximum": 1000},
                {"key": "engine_max", "label": "Worker maksimum", "kind": "number", "default": 10, "minimum": 1, "maximum": 1000},
                {"key": "engine_lag_target", "label": "Target antrean per worker", "kind": "number", "default": 100, "minimum": 1, "maximum": 10000},
                {"key": "api_min", "label": "API minimum", "kind": "number", "default": 3, "minimum": 1, "maximum": 1000},
                {"key": "api_max", "label": "API maksimum", "kind": "number", "default": 10, "minimum": 1, "maximum": 1000},
                {"key": "api_cpu_target", "label": "Target CPU API (%)", "kind": "number", "default": 70, "minimum": 10, "maximum": 95},
                {"key": "web_min", "label": "Web minimum", "kind": "number", "default": 2, "minimum": 1, "maximum": 1000},
                {"key": "web_max", "label": "Web maksimum", "kind": "number", "default": 6, "minimum": 1, "maximum": 1000},
                {"key": "web_cpu_target", "label": "Target CPU Web (%)", "kind": "number", "default": 70, "minimum": 10, "maximum": 95},
            ]}


def _cluster_or_404(s: Session, cluster_id: str) -> db.Cluster:
    cluster = s.get(db.Cluster, cluster_id)
    if not cluster:
        raise HTTPException(404, "cluster tidak ditemukan")
    return cluster


def _stored_cluster_config(s: Session, cluster_id: str) -> dict:
    row = s.get(db.ClusterConfiguration, cluster_id)
    if row:
        try:
            return decrypt_config(row.encrypted_payload)
        except RuntimeError as exc:
            raise HTTPException(503, str(exc)) from exc
    defaults = {key: item["default"] for key, item in CONFIG_CATALOG.items() if item.get("default") is not None and not item["secret"]}
    return {"settings": defaults, "secrets": {}, "autoscaling": {}, "connectors": []}


@app.get("/api/v1/clusters/{cluster_id}/configuration")
def read_cluster_configuration(cluster_id: str, p=Depends(need_admin), s: Session = Depends(db.dep)):
    _cluster_or_404(s, cluster_id)
    config = _stored_cluster_config(s, cluster_id)
    row = s.get(db.ClusterConfiguration, cluster_id)
    return {"cluster_id": cluster_id, "version": row.version if row else 0, **public_config(config)}


@app.put("/api/v1/clusters/{cluster_id}/configuration")
def save_cluster_configuration(cluster_id: str, body: ClusterConfigurationIn, p=Depends(need_admin), s: Session = Depends(db.dep)):
    _cluster_or_404(s, cluster_id)
    previous = _stored_cluster_config(s, cluster_id)
    if len(set(body.clear_secrets)) != len(body.clear_secrets):
        raise HTTPException(422, "clear_secrets tidak boleh berisi duplikat")
    if set(body.clear_secrets) - SECRET_KEYS:
        raise HTTPException(422, "clear_secrets berisi nama secret yang tidak dikenal")
    if set(body.clear_secrets) & body.secrets.keys():
        raise HTTPException(422, "secret tidak dapat diatur dan dihapus pada permintaan yang sama")
    secrets = {**previous.get("secrets", {}), **{key: value for key, value in body.secrets.items() if value}}
    for key in body.clear_secrets:
        secrets.pop(key, None)
    candidate = body.model_dump(exclude={"clear_secrets"})
    candidate["secrets"] = secrets
    try:
        config = validate_config(candidate)
        encrypted = encrypt_config(config)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(422 if isinstance(exc, ValueError) else 503, str(exc)) from exc
    row = s.get(db.ClusterConfiguration, cluster_id)
    if row is None:
        row = db.ClusterConfiguration(cluster_id=cluster_id, version=0)
        s.add(row)
    row.version += 1
    row.encrypted_payload = encrypted
    row.issued_at = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    row.updated_by = p[0]
    audit(s, p[0], "cluster.configuration.publish", cluster_id, {"version": row.version, "connectors": len(config["connectors"])})
    s.commit()
    return {"cluster_id": cluster_id, "version": row.version, **public_config(config)}


def _cluster_auth(s: Session, cluster_id: str, authorization: str):
    cluster = s.get(db.Cluster, cluster_id)
    token = authorization.removeprefix("Bearer ").strip()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    if not cluster or not token or not hmac.compare_digest(token_hash, cluster.pull_token_hash):
        raise HTTPException(401, "token cluster tidak valid")
    return cluster


@app.get("/api/v1/config/pull/{cluster_id}")
def pull_cluster_configuration(cluster_id: str, authorization: str = Header(default=""),
                               if_none_match: str = Header(default="0"), s: Session = Depends(db.dep)):
    _cluster_auth(s, cluster_id, authorization)
    row = s.get(db.ClusterConfiguration, cluster_id)
    if not row or str(row.version) == if_none_match.strip('"'):
        return Response(status_code=304)
    try:
        config = decrypt_config(row.encrypted_payload)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
    return sign_payload(_key(), cluster_id, row.version, config, row.issued_at)


# ---------------- kebijakan
@app.post("/api/v1/policies", status_code=201)
def publish(body: PolicyIn, p=Depends(need_admin), s: Session = Depends(db.dep)):
    try:
        pol = validate_policy(body.policy)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(422, f"kebijakan tidak valid / melanggar batas keamanan: {str(e)[:400]}") from e
    known = {c for (c,) in s.execute(select(db.Cluster.id))}
    bad = [t for t in body.targets if t != "*" and t not in known]
    if bad:
        raise HTTPException(422, f"target tidak dikenal: {bad}")
    _key()   # gagal cepat bila kunci tidak ada
    row = db.PolicyRow(policy=pol.model_dump(exclude_none=True), targets=sorted(set(body.targets)), note=body.note, issued_at=utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), created_by=p[0])
    s.add(row); s.flush()
    audit(s, p[0], "policy.publish", str(row.version), {"targets": row.targets, "note": body.note})
    s.commit()
    return {"version": row.version, "targets": row.targets}


@app.get("/api/v1/policies")
def policies(p=Depends(principal), s: Session = Depends(db.dep)):
    return [{"version": r.version, "targets": r.targets, "note": r.note, "created_by": r.created_by, "issued_at": r.issued_at, "policy": r.policy}
            for r in s.scalars(select(db.PolicyRow).order_by(db.PolicyRow.version.desc()).limit(100))]


@app.post("/api/v1/policies/{version}/republish", status_code=201)
def republish(version: int, targets: list[str], p=Depends(need_admin), s: Session = Depends(db.dep)):
    """Rollback = terbitkan ulang ISI versi lama sebagai versi BARU (versi cluster tidak pernah mundur -> anti-replay)."""
    old = s.get(db.PolicyRow, version)
    if not old:
        raise HTTPException(404, "versi tidak ada")
    return publish(PolicyIn(policy=old.policy, targets=targets, note=f"rollback ke isi v{version}"), p, s)


@app.get("/api/v1/policy/{cluster_id}")
def pull(cluster_id: str, request: Request, authorization: str = Header(default=""), if_none_match: str = Header(default="0"), s: Session = Depends(db.dep)):
    """Dipanggil cluster (bukan manusia). Auth = token tarik milik cluster tsb. Respons bertanda tangan untuk cluster itu saja."""
    cl = s.get(db.Cluster, cluster_id)
    t = hashlib.sha256(authorization.removeprefix("Bearer ").strip().encode()).hexdigest()
    if not cl or not hmac.compare_digest(t, cl.pull_token_hash):
        raise HTTPException(401, "token cluster tidak valid")
    st = s.get(db.StatusRow, cluster_id) or db.StatusRow(cluster_id=cluster_id)
    st.last_policy_fetch = utcnow(); s.merge(st); s.commit()
    row = effective(s, cluster_id)
    if row is None or str(row.version) == if_none_match.strip('"'):
        return Response(status_code=304)
    return sign(_key(), cluster_id, row.version, row.policy, row.issued_at)


@app.get("/api/v1/audit")
def audit_log(p=Depends(need_admin), s: Session = Depends(db.dep)):
    return [{"ts": a.ts.isoformat(), "actor": a.actor, "action": a.action, "target": a.target, "detail": a.detail}
            for a in s.scalars(select(db.MAudit).order_by(db.MAudit.id.desc()).limit(200))]
