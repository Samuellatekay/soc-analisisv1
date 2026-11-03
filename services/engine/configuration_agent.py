"""Verify Master configuration bundles and apply them to this Kubernetes namespace."""
from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
from pathlib import Path
from urllib.parse import unquote, urlparse

import httpx

from services.common.config import read_secret
from services.master.policy import PolicyRejected, verify_signed_payload

log = logging.getLogger("configuration_agent")
_ANNOTATION = "soc-analisis/config-managed-keys"


class KubernetesClient:
    def __init__(self, namespace: str | None = None, transport=None):
        self.namespace = namespace or Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read_text().strip()
        token_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
        ca_path = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
        token = token_path.read_text().strip()
        host = os.getenv("KUBERNETES_SERVICE_HOST")
        port = os.getenv("KUBERNETES_SERVICE_PORT_HTTPS", "443")
        if not host or not token:
            raise RuntimeError("configuration agent harus berjalan di Kubernetes dengan service account token")
        self.http = httpx.Client(
            base_url=f"https://{host}:{port}",
            headers={"Authorization": f"Bearer {token}"},
            verify=str(ca_path),
            timeout=10,
            transport=transport,
        )

    def request(self, method: str, path: str, body: dict | None = None, content_type: str = "application/json"):
        response = self.http.request(
            method, path, json=body,
            headers={"Content-Type": content_type} if body is not None else None,
        )
        if response.status_code >= 400:
            if response.status_code == 404:
                return None
            raise RuntimeError(f"Kubernetes API {method} {path}: HTTP {response.status_code}")
        return response.json() if response.content else {}

    def apply(self, resource_path: str, collection_path: str, body: dict):
        current = self.request("GET", resource_path)
        if current is None:
            return self.request("POST", collection_path, body)
        return self.request("PATCH", resource_path, body, "application/merge-patch+json")

    def delete(self, path: str):
        response = self.http.delete(path)
        if response.status_code not in (200, 202, 204, 404):
            raise RuntimeError(f"Kubernetes API DELETE {path}: HTTP {response.status_code}")


class ConfigAgent:
    def __init__(self, master_url: str, cluster_id: str, token: str, public_key: str,
                 kubernetes: KubernetesClient, transport=None, timeout: float = 10,
                 verify: bool | str = True):
        if not all((master_url, cluster_id, token, public_key)):
            raise ValueError("MASTER_URL, CLUSTER_ID, MASTER_CLUSTER_TOKEN, MASTER_POLICY_PUBKEY wajib")
        self.url = master_url.rstrip("/")
        self.cluster_id = cluster_id
        self.public_key = public_key.strip()
        self.kubernetes = kubernetes
        self.http = httpx.Client(
            timeout=timeout, transport=transport,
            headers={"Authorization": f"Bearer {token}"},
            verify=verify,
        )

    @classmethod
    def from_env(cls, transport=None, kubernetes=None):
        key_path = os.getenv("MASTER_POLICY_PUBKEY_FILE", "")
        public_key = Path(key_path).read_text() if key_path and Path(key_path).exists() else os.getenv("MASTER_POLICY_PUBKEY", "")
        ca_path = os.getenv("MASTER_CA_CERT_FILE", "")
        if ca_path and not Path(ca_path).is_file():
            raise ValueError(f"sertifikat CA Master tidak ditemukan: {ca_path}")
        return cls(
            os.getenv("MASTER_URL", ""),
            os.getenv("CLUSTER_ID", ""),
            read_secret("MASTER_CLUSTER_TOKEN"),
            public_key,
            kubernetes or KubernetesClient(),
            transport,
            verify=ca_path or True,
        )

    def _current_version(self) -> int:
        path = f"/api/v1/namespaces/{self.kubernetes.namespace}/configmaps/soc-config"
        resource = self.kubernetes.request("GET", path)
        if not resource:
            raise RuntimeError("ConfigMap soc-config tidak ditemukan")
        try:
            return int((resource.get("data") or {}).get("MASTER_CONFIG_VERSION", "0"))
        except ValueError as exc:
            raise RuntimeError("MASTER_CONFIG_VERSION pada soc-config tidak valid") from exc

    def check(self) -> dict:
        applied = self._current_version()
        response = self.http.get(
            f"{self.url}/api/v1/config/pull/{self.cluster_id}",
            headers={"If-None-Match": str(applied)},
        )
        if response.status_code == 304:
            return {"status": "up_to_date", "version": applied}
        response.raise_for_status()
        bundle = response.json()
        try:
            config = verify_signed_payload(bundle, self.public_key, self.cluster_id, applied)
        except PolicyRejected as exc:
            raise RuntimeError(str(exc)) from exc
        version = bundle["version"]
        self.apply(config, version)
        return {"status": "applied", "version": version}

    def apply(self, config: dict, version: int):
        settings = config.get("settings", {})
        secrets = config.get("secrets", {})
        scaling = config.get("autoscaling", {})
        runtime_data, runtime_secrets, connector_secrets = _split_settings(settings, secrets)
        runtime_data["MASTER_CONFIG_VERSION"] = str(version)
        connector_data = {"connectors.json": json.dumps({"connectors": config.get("connectors", [])}, separators=(",", ":"))}

        if scaling.get("enabled"):
            _validate_redis_scaling(settings, secrets)
            self._apply_autoscaling(scaling, settings, secrets)
        else:
            self._disable_autoscaling()

        _apply_configmap(self.kubernetes, "soc-config", runtime_data)
        _apply_secret(self.kubernetes, "soc-runtime", runtime_secrets)
        _apply_secret(self.kubernetes, "soc-connectors", connector_secrets)
        _apply_configmap(self.kubernetes, "soc-connectors-config", connector_data)
        self._rollout(version, settings)

    def _apply_autoscaling(self, scaling: dict, settings: dict, secrets: dict):
        namespace = self.kubernetes.namespace
        api_root = f"/apis/keda.sh/v1alpha1/namespaces/{namespace}"
        available = self.kubernetes.request("GET", "/apis/keda.sh/v1alpha1")
        if not available:
            raise RuntimeError("KEDA belum terpasang di cluster; pasang KEDA 2.16+ sebelum mengaktifkan autoscaling")

        redis_url = secrets["REDIS_URL"]
        parsed = urlparse(redis_url)
        password = unquote(parsed.password) if parsed.password else ""
        username = unquote(parsed.username) if parsed.username else ""
        auth_data = {}
        auth_refs = []
        if password:
            auth_data["password"] = password
            auth_refs.append({"parameter": "password", "name": "soc-keda-redis", "key": "password"})
        if username:
            auth_data["username"] = username
            auth_refs.append({"parameter": "username", "name": "soc-keda-redis", "key": "username"})
        if auth_data:
            secret_path = f"/api/v1/namespaces/{namespace}/secrets/soc-keda-redis"
            secret_collection = f"/api/v1/namespaces/{namespace}/secrets"
            self.kubernetes.apply(secret_path, secret_collection, {
                "apiVersion": "v1", "kind": "Secret",
                "metadata": {"name": "soc-keda-redis", "namespace": namespace},
                "type": "Opaque",
                "data": {key: base64.b64encode(value.encode()).decode() for key, value in auth_data.items()},
            })
            self.kubernetes.apply(f"{api_root}/triggerauthentications/soc-keda-redis",
                                 f"{api_root}/triggerauthentications", {
                "apiVersion": "keda.sh/v1alpha1", "kind": "TriggerAuthentication",
                "metadata": {"name": "soc-keda-redis", "namespace": namespace},
                "spec": {"secretTargetRef": auth_refs},
            })

        scaler_metadata = {
            "address": f"{parsed.hostname}:{parsed.port or (6380 if parsed.scheme == 'rediss' else 6379)}",
            "stream": "soc:events",
            "consumerGroup": "engine",
            "lagCount": str(scaling["engine_lag_target"]),
            "activationLagCount": "0",
            "databaseIndex": (parsed.path or "/0").lstrip("/") or "0",
        }
        if parsed.scheme == "rediss":
            scaler_metadata["enableTLS"] = "true"
        scaled_object = {
            "apiVersion": "keda.sh/v1alpha1", "kind": "ScaledObject",
            "metadata": {"name": "engine-autoscaler", "namespace": namespace},
            "spec": {
                "scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "engine"},
                "pollingInterval": 15, "cooldownPeriod": 60,
                "minReplicaCount": scaling["engine_min"], "maxReplicaCount": scaling["engine_max"],
                "triggers": [{"type": "redis-streams", "metadata": scaler_metadata,
                              **({"authenticationRef": {"name": "soc-keda-redis"}} if auth_refs else {})}],
            },
        }
        self.kubernetes.apply(f"{api_root}/scaledobjects/engine-autoscaler", f"{api_root}/scaledobjects", scaled_object)
        if not auth_refs:
            self.kubernetes.delete(f"{api_root}/triggerauthentications/soc-keda-redis")
            self.kubernetes.delete(f"/api/v1/namespaces/{namespace}/secrets/soc-keda-redis")

        autoscaling_root = f"/apis/autoscaling/v2/namespaces/{namespace}"
        for component in ("api", "web"):
            hpa = {
                "apiVersion": "autoscaling/v2", "kind": "HorizontalPodAutoscaler",
                "metadata": {"name": f"soc-{component}", "namespace": namespace},
                "spec": {
                    "scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": component},
                    "minReplicas": scaling[f"{component}_min"], "maxReplicas": scaling[f"{component}_max"],
                    "metrics": [{"type": "Resource", "resource": {"name": "cpu", "target": {
                        "type": "Utilization", "averageUtilization": scaling[f"{component}_cpu_target"]}}}],
                },
            }
            self.kubernetes.apply(
                f"{autoscaling_root}/horizontalpodautoscalers/soc-{component}",
                f"{autoscaling_root}/horizontalpodautoscalers", hpa,
            )

    def _disable_autoscaling(self):
        namespace = self.kubernetes.namespace
        for path in (
            f"/apis/keda.sh/v1alpha1/namespaces/{namespace}/scaledobjects/engine-autoscaler",
            f"/apis/keda.sh/v1alpha1/namespaces/{namespace}/triggerauthentications/soc-keda-redis",
            f"/apis/autoscaling/v2/namespaces/{namespace}/horizontalpodautoscalers/soc-api",
            f"/apis/autoscaling/v2/namespaces/{namespace}/horizontalpodautoscalers/soc-web",
            f"/api/v1/namespaces/{namespace}/secrets/soc-keda-redis",
        ):
            self.kubernetes.delete(path)

    def _rollout(self, version: int, settings: dict):
        namespace = self.kubernetes.namespace
        deployments = ("api", "engine", "rag-worker", "indexer", "connectors", "kb-sync", "configuration-agent")
        for name in deployments:
            self.kubernetes.request(
                "PATCH", f"/apis/apps/v1/namespaces/{namespace}/deployments/{name}",
                {"spec": {"template": {"metadata": {"annotations": {"soc-analisis/config-version": str(version)}}}}},
                "application/merge-patch+json",
            )
        backup_spec = {"jobTemplate": {"spec": {"template": {"metadata": {"annotations": {
            "soc-analisis/config-version": str(version),
        }}}}}}
        if "BACKUP_ENABLED" in settings:
            backup_spec["suspend"] = not settings["BACKUP_ENABLED"]
        if "BACKUP_SCHEDULE_CRON" in settings:
            backup_spec["schedule"] = settings["BACKUP_SCHEDULE_CRON"]
        if "BACKUP_TIMEZONE" in settings:
            backup_spec["timeZone"] = settings["BACKUP_TIMEZONE"]
        self.kubernetes.request(
            "PATCH", f"/apis/batch/v1/namespaces/{namespace}/cronjobs/backup",
            {"spec": backup_spec}, "application/merge-patch+json",
        )


def _validate_redis_scaling(settings: dict, secrets: dict):
    if settings.get("INGEST_MODE") != "queue":
        raise RuntimeError("autoscaling engine memerlukan INGEST_MODE=queue")
    parsed = urlparse(secrets.get("REDIS_URL", ""))
    if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
        raise RuntimeError("autoscaling engine memerlukan REDIS_URL redis:// atau rediss:// yang valid")


def _split_settings(settings: dict, secrets: dict) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    connector_keys = {"SPLUNK_TOKEN", "SENTINEL_CLIENT_SECRET", "QRADAR_TOKEN", "CS_CLIENT_SECRET",
                     "S1_API_TOKEN", "DEFENDER_CLIENT_SECRET", "CORTEX_API_KEY", "WAZUH_INDEXER_PASSWORD", "ELASTIC_API_KEY"}
    data = {
        key: json.dumps(value, separators=(",", ":")) if isinstance(value, (dict, list)) else str(value)
        for key, value in settings.items()
    }
    runtime = {key: value for key, value in secrets.items() if key not in connector_keys}
    connectors = {key: value for key, value in secrets.items() if key in connector_keys}
    return data, runtime, connectors


def _apply_configmap(kubernetes: KubernetesClient, name: str, values: dict[str, str]):
    namespace = kubernetes.namespace
    path = f"/api/v1/namespaces/{namespace}/configmaps/{name}"
    resource = kubernetes.request("GET", path)
    if resource is None:
        raise RuntimeError(f"ConfigMap {name} tidak ditemukan")
    annotations = resource.setdefault("metadata", {}).setdefault("annotations", {})
    old_keys = set(json.loads(annotations.get(_ANNOTATION, "[]")))
    data = resource.setdefault("data", {})
    for key in old_keys - values.keys():
        data.pop(key, None)
    data.update(values)
    annotations[_ANNOTATION] = json.dumps(sorted(values))
    kubernetes.request("PATCH", path, {"data": data, "metadata": {"annotations": annotations}},
                       "application/merge-patch+json")


def _apply_secret(kubernetes: KubernetesClient, name: str, values: dict[str, str]):
    namespace = kubernetes.namespace
    collection = f"/api/v1/namespaces/{namespace}/secrets"
    path = f"{collection}/{name}"
    resource = kubernetes.request("GET", path)
    annotations = (resource or {}).get("metadata", {}).get("annotations", {})
    old_keys = set(json.loads(annotations.get(_ANNOTATION, "[]")))
    data = dict((resource or {}).get("data") or {})
    for key in old_keys - values.keys():
        data.pop(key, None)
    data.update({key: base64.b64encode(value.encode()).decode() for key, value in values.items()})
    body = {
        "apiVersion": "v1", "kind": "Secret",
        "metadata": {"name": name, "namespace": namespace, "annotations": {_ANNOTATION: json.dumps(sorted(values))}},
        "type": (resource or {}).get("type", "Opaque"),
        "data": data,
    }
    kubernetes.apply(path, collection, body)


def loop(agent: ConfigAgent, interval: float = 60, stop: threading.Event | None = None):
    stop = stop or threading.Event()
    while not stop.is_set():
        try:
            result = agent.check()
            if result["status"] != "up_to_date":
                log.info("konfigurasi Master: %s", result)
        except Exception:
            log.exception("gagal menarik/menerapkan konfigurasi Master; setting terpasang tetap dipertahankan")
        stop.wait(interval)


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    agent = ConfigAgent.from_env()
    loop(agent, float(os.getenv("MASTER_CONFIG_POLL_SECONDS", "60")))


if __name__ == "__main__":
    main()
