from __future__ import annotations

import re
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import Principal, audit, require
from services.common.config import get_settings
from services.common.db import get_session
from services.common.models import ConnectorConfig, ConnectorState
from services.common.util import utcnow
from services.engine.adapters.catalog import CATALOG, catalog_response
from services.engine.adapters.runner import connector_configs

router = APIRouter(prefix="/connectors", tags=["connectors"])
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")


class ConnectorConfigBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=64)
    type: str
    enabled: bool = False
    poll_seconds: int = Field(default=60, ge=10, le=86400)
    batch_size: int = Field(default=500, ge=1, le=10000)
    initial_lookback_hours: int = Field(default=24, ge=1, le=8760)
    params: dict[str, object] = Field(default_factory=dict)


def _configured(tenant: str) -> list[dict]:
    return [c for c in connector_configs(get_settings()) if c.get("tenant_id", "default") == tenant]


def _validate_config(body: ConnectorConfigBody) -> dict:
    if not _NAME.fullmatch(body.name):
        raise HTTPException(422, "nama hanya boleh berisi huruf, angka, titik, garis bawah, dan tanda hubung")
    spec = CATALOG.get(body.type)
    if not spec:
        raise HTTPException(422, "tipe konektor tidak didukung")
    fields = {item["key"]: item for item in spec["fields"]}
    unknown = set(body.params) - fields.keys()
    if unknown:
        raise HTTPException(422, f"parameter tidak dikenal: {', '.join(sorted(unknown))}")
    params = {}
    for key, field in fields.items():
        value = body.params.get(key, field.get("default"))
        if value is None or value == "":
            if field["required"]:
                raise HTTPException(422, f"parameter wajib: {field['label']}")
            continue
        kind = field["kind"]
        if kind == "boolean":
            if not isinstance(value, bool):
                raise HTTPException(422, f"parameter {key} harus berupa boolean")
        elif kind == "number":
            if isinstance(value, bool) or not isinstance(value, int):
                raise HTTPException(422, f"parameter {key} harus berupa bilangan bulat")
            if not 1 <= value <= 10000:
                raise HTTPException(422, f"parameter {key} di luar rentang yang diizinkan")
        elif not isinstance(value, str) or len(value) > 2048:
            raise HTTPException(422, f"parameter {key} harus berupa teks (maksimal 2048 karakter)")
        elif field.get("required") and not value.strip():
            raise HTTPException(422, f"parameter wajib: {field['label']}")
        if kind == "secret_ref" and not _ENV_NAME.fullmatch(value):
            raise HTTPException(422, f"{key} harus berisi nama environment variable, bukan secret aslinya")
        if key == "base_url":
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                raise HTTPException(422, "URL layanan harus berupa http(s) URL tanpa kredensial di URL")
        if kind == "select" and value not in field["options"]:
            raise HTTPException(422, f"nilai {key} tidak didukung")
        params[key] = value
    return {
        "name": body.name,
        "type": body.type,
        "enabled": body.enabled,
        "poll_seconds": body.poll_seconds,
        "batch_size": body.batch_size,
        "initial_lookback_hours": body.initial_lookback_hours,
        "params": params,
    }


@router.get("/catalog")
def connector_catalog(p: Principal = Depends(require("admin"))):
    return catalog_response()


@router.get("/config")
def connector_configs_for_ui(p: Principal = Depends(require("admin"))):
    """Return admin-editable configuration; secret material is never stored here."""
    return _configured(p.tenant_id)


@router.put("/config/{name}")
def save_connector_config(name: str, body: ConnectorConfigBody, p: Principal = Depends(require("admin")),
                          db: Session = Depends(get_session)):
    if name != body.name:
        raise HTTPException(422, "nama pada URL dan konfigurasi harus sama")
    config = _validate_config(body)
    all_configs = connector_configs(get_settings())
    if any(c["name"] == name and c.get("tenant_id", "default") != p.tenant_id for c in all_configs):
        raise HTTPException(409, "nama konektor sudah digunakan tenant lain")
    saved = db.get(ConnectorConfig, (p.tenant_id, name))
    if saved is None:
        saved = ConnectorConfig(tenant_id=p.tenant_id, name=name)
        db.add(saved)
    saved.type = config["type"]
    saved.enabled = config["enabled"]
    saved.poll_seconds = config["poll_seconds"]
    saved.batch_size = config["batch_size"]
    saved.initial_lookback_hours = config["initial_lookback_hours"]
    saved.params = config["params"]
    audit(db, p, "connector.config.save", name, {"type": saved.type, "enabled": saved.enabled})
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "nama konektor sudah digunakan") from exc
    config["tenant_id"] = p.tenant_id
    return config


@router.get("")
def list_connectors(p: Principal = Depends(require("analyst")), db: Session = Depends(get_session)):
    """Status konektor milik tenant. `params` (host/credential) sengaja TIDAK dikembalikan."""
    out = []
    for c in _configured(p.tenant_id):
        st = db.get(ConnectorState, c["name"])
        lag = None
        if st and st.last_success:
            lag = int((utcnow() - st.last_success).total_seconds())
        out.append({"name": c["name"], "type": c["type"], "enabled": c.get("enabled", False), "poll_seconds": c.get("poll_seconds", 60),
                    "state": None if not st else {"cursor": st.cursor, "last_success": st.last_success.isoformat() if st.last_success else None,
                                                  "seconds_since_success": lag, "last_error": st.last_error, "last_warning": st.last_warning,
                                                  "consecutive_failures": st.consecutive_failures, "events_total": st.events_total,
                                                  "rejected_total": st.rejected_total, "mapping_version": st.mapping_version}})
    return out


@router.post("/{name}/test")
def test_connector(name: str, p: Principal = Depends(require("admin")), db: Session = Depends(get_session)):
    """Uji auth+koneksi+format dengan mengambil <=1 event; tidak menyimpan event maupun memajukan cursor."""
    from services.engine.adapters.runner import load_connectors
    if name not in {c["name"] for c in _configured(p.tenant_id)}:   # cek tenant SEBELUM menginstansiasi apa pun
        raise HTTPException(404, "konektor tidak ditemukan")
    found = [c for c, _ in load_connectors(get_settings(), only_enabled=False, name=name)]
    if not found:
        return {"ok": False, "error": "konfigurasi konektor tidak valid (parameter wajib kurang)"}
    audit(db, p, "connector.test", name)
    db.commit()
    try:
        return found[0].test()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}"[:300]}
