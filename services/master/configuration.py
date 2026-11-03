"""Master-managed cluster settings and encrypted-at-rest configuration payloads."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

from cryptography.fernet import Fernet, InvalidToken

from services.engine.adapters.catalog import CATALOG as CONNECTOR_CATALOG


def field(key: str, label: str, kind: str = "text", *, secret: bool = False, default=None,
          options: list[str] | None = None, minimum: int | float | None = None,
          maximum: int | float | None = None, help: str = "") -> dict:
    return {"key": key, "label": label, "kind": kind, "secret": secret, "default": default,
            "options": options or [], "minimum": minimum, "maximum": maximum, "help": help}


_FIELDS = [
    ("Aplikasi", field("DATABASE_URL", "PostgreSQL URL", secret=True, help="Gunakan postgresql+psycopg://; PostgreSQL dapat berada di luar cluster.")),
    ("Aplikasi", field("INGEST_MODE", "Mode ingest", "select", default="queue", options=["inline", "queue"])),
    ("Aplikasi", field("EMBEDDED_WORKERS", "Worker tertanam di API", "boolean", default=False)),
    ("Aplikasi", field("EMBEDDED_CONNECTORS", "Konektor tertanam di API", "boolean", default=False)),
    ("Aplikasi", field("API_TOKENS", "Token API (format token:role:tenant)", secret=True)),
    ("Aplikasi", field("INGEST_API_KEY", "Kunci ingest", secret=True)),
    ("Aplikasi", field("MAX_PAYLOAD_BYTES", "Batas payload ingest (byte)", "number", default=262144, minimum=1024, maximum=10485760)),
    ("Autentikasi", field("OIDC_ISSUER", "OIDC issuer")),
    ("Autentikasi", field("OIDC_AUDIENCE", "OIDC audience", default="soc-api")),
    ("Autentikasi", field("OIDC_CLIENT_ID", "OIDC client ID", default="soc-ui")),
    ("Autentikasi", field("OIDC_SCOPE", "OIDC scope", default="openid profile email")),
    ("Autentikasi", field("OIDC_AUTH_URL", "OIDC authorization URL")),
    ("Autentikasi", field("OIDC_TOKEN_URL", "OIDC token URL")),
    ("Autentikasi", field("OIDC_LOGOUT_URL", "OIDC logout URL")),
    ("Autentikasi", field("OIDC_JWKS_URL", "OIDC JWKS URL")),
    ("Autentikasi", field("OIDC_AUTH_EXTRA_PARAMS", "OIDC extra parameters JSON", "json", default="{}")),
    ("Autentikasi", field("OIDC_ROLE_CLAIM", "OIDC role claim", default="roles")),
    ("Autentikasi", field("OIDC_ROLE_MAP", "OIDC role mapping JSON", "json", default='{"soc-admin":"admin","soc-analyst":"analyst","soc-viewer":"viewer"}')),
    ("Autentikasi", field("OIDC_TENANT_CLAIM", "OIDC tenant claim", default="tenant_id")),
    ("Autentikasi", field("ALLOW_STATIC_TOKENS", "Izinkan token statis bersama OIDC", "boolean", default=False)),
    ("Data eksternal", field("REDIS_URL", "Redis URL", secret=True, help="Diperlukan untuk queue dan autoscaling worker.")),
    ("Data eksternal", field("ELASTICSEARCH_URL", "Elasticsearch URL", help="Elasticsearch/OpenSearch dapat berada di luar cluster; gunakan HTTPS produksi.")),
    ("Data eksternal", field("ELASTICSEARCH_API_KEY", "Elasticsearch API key", secret=True)),
    ("Data eksternal", field("ELASTICSEARCH_INDEX", "Nama index Elasticsearch", default="soc-alerts-v1")),
    ("Data eksternal", field("NEO4J_URI", "Neo4j URI")),
    ("Data eksternal", field("NEO4J_USER", "Neo4j username", default="neo4j")),
    ("Data eksternal", field("NEO4J_PASSWORD", "Neo4j password", secret=True)),
    ("AI", field("LLM_PROVIDER", "Provider AI", "select", default="none", options=["auto", "none", "ollama", "openai", "gemini", "openai_compatible"])),
    ("AI", field("LLM_MODEL", "Nama model AI")),
    ("AI", field("LLM_API_KEY", "AI API key", secret=True)),
    ("AI", field("LLM_BASE_URL", "AI base URL")),
    ("AI", field("LLM_TIMEOUT", "AI timeout (detik)", "number", default=60, minimum=1, maximum=600)),
    ("AI", field("OLLAMA_URL", "Ollama URL")),
    ("AI", field("OLLAMA_MODEL", "Ollama model")),
    ("AI", field("OLLAMA_TIMEOUT", "Ollama timeout (detik)", "number", default=60, minimum=1, maximum=600)),
    ("AI", field("PROMPT_VERSION", "Prompt version", default="analysis_v1")),
    ("AI", field("BERT_MODEL_PATH", "BERT model path")),
    ("Konektor", field("SPLUNK_TOKEN", "Splunk token", secret=True)),
    ("Konektor", field("SENTINEL_CLIENT_SECRET", "Sentinel client secret", secret=True)),
    ("Konektor", field("QRADAR_TOKEN", "QRadar token", secret=True)),
    ("Konektor", field("CS_CLIENT_SECRET", "CrowdStrike client secret", secret=True)),
    ("Konektor", field("S1_API_TOKEN", "SentinelOne API token", secret=True)),
    ("Konektor", field("DEFENDER_CLIENT_SECRET", "Defender client secret", secret=True)),
    ("Konektor", field("CORTEX_API_KEY", "Cortex API key", secret=True)),
    ("Konektor", field("WAZUH_INDEXER_PASSWORD", "Wazuh password", secret=True)),
    ("Konektor", field("ELASTIC_API_KEY", "Elastic connector API key", secret=True)),
    ("Aset & Intel", field("GLPI_URL", "GLPI URL")),
    ("Aset & Intel", field("GLPI_CONFIG", "Path konfigurasi GLPI", default="/app/infra/config/glpi.json", help="File harus tersedia melalui image atau volume mount pada setiap workload.")),
    ("Aset & Intel", field("GLPI_INSECURE_TLS", "Nonaktifkan verifikasi TLS GLPI", "boolean", default=False, help="Tidak disarankan; hanya aktifkan jika endpoint memakai sertifikat internal yang tidak dipercaya.")),
    ("Aset & Intel", field("GLPI_APP_TOKEN", "GLPI app token", secret=True)),
    ("Aset & Intel", field("GLPI_USER_TOKEN", "GLPI user token", secret=True)),
    ("Aset & Intel", field("ASSET_INVENTORY_FILE", "Path file inventaris aset", default="/app/data/assets.json", help="File harus tersedia melalui image atau volume mount pada setiap workload.")),
    ("Aset & Intel", field("INTEL_FILE", "Path file intel lokal", default="/app/data/intel.json", help="File harus tersedia melalui image atau volume mount pada setiap workload.")),
    ("Aset & Intel", field("VULN_FILE", "Path file kerentanan lokal", default="/app/data/vulns.json", help="File harus tersedia melalui image atau volume mount pada setiap workload.")),
    ("Aset & Intel", field("OPENCTI_URL", "OpenCTI URL")),
    ("Aset & Intel", field("OPENCTI_TOKEN", "OpenCTI token", secret=True)),
    ("Knowledge base", field("KB_SEED_FILE", "Path seed knowledge base", default="/app/data/kb_seed.json", help="File harus tersedia melalui image atau volume mount pada workload kb-sync.")),
    ("Enrichment", field("ENRICHMENT_TIMEOUT", "Enrichment timeout (detik)", "number", default=2.0, minimum=0.1, maximum=60)),
    ("Enrichment", field("ENRICHMENT_CACHE_TTL", "Cache TTL (detik)", "number", default=300, minimum=0, maximum=86400)),
    ("Analisis", field("FFT_MIN_HISTORY_HOURS", "Minimum histori FFT (jam)", "number", default=48, minimum=1, maximum=8760)),
    ("Analisis", field("FFT_PEAK_RATIO", "Rasio puncak FFT", "number", default=3.0, minimum=0, maximum=100)),
    ("Analisis", field("PCC_THRESHOLD", "Ambang PCC", "number", default=0.85, minimum=0, maximum=1)),
    ("Analisis", field("ENV_INDUSTRY_CAMPAIGN", "Konteks kampanye industri", "boolean", default=False)),
    ("Analisis", field("ENV_NETWORK_WIDE_ANOMALY", "Anomali jaringan luas", "boolean", default=False)),
    ("Analisis", field("SCORING_CONFIG", "Path file konfigurasi scoring", default="/app/infra/config/scoring_v1.json", help="File harus tersedia melalui image atau volume mount pada setiap workload.")),
    ("Analisis", field("RULES_CONFIG", "Path file rules", default="/app/infra/config/rules.json", help="File harus tersedia melalui image atau volume mount pada setiap workload.")),
    ("Knowledge base", field("KB_SYNC_HOUR", "Jam sinkronisasi KB", "number", default=1, minimum=0, maximum=23)),
    ("Knowledge base", field("KB_SYNC_TZ", "Zona waktu KB", default="Asia/Jakarta")),
    ("Knowledge base", field("KB_STALE_DAYS", "KB stale setelah (hari)", "number", default=3, minimum=1, maximum=365)),
    ("Backup", field("BACKUP_ENABLED", "Backup aktif", "boolean", default=True, help="Memerlukan BACKUP_ENCRYPTION_KEY dan volume repository yang tersedia di cluster.")),
    ("Backup", field("BACKUP_SCHEDULE_MODE", "Mode jadwal backup", "select", default="cron", options=["cron"])),
    ("Backup", field("BACKUP_SCHEDULE_CRON", "Jadwal backup cron", default="0 2 * * *")),
    ("Backup", field("BACKUP_TIMEZONE", "Zona waktu backup", default="Asia/Jakarta")),
    ("Backup", field("BACKUP_COMPONENTS", "Komponen backup (pisahkan koma)", default="postgres,elasticsearch,neo4j,redis")),
    ("Backup", field("BACKUP_RETENTION_DAYS", "Retensi backup (hari)", "number", default=30, minimum=1, maximum=3650)),
    ("Backup", field("BACKUP_REPOSITORY_URI", "Lokasi backup", default="/backups")),
    ("Backup", field("BACKUP_VERIFY_AFTER_RUN", "Verifikasi setelah backup", "boolean", default=True)),
    ("Backup", field("BACKUP_ENCRYPTION_KEY", "Kunci enkripsi backup", secret=True)),
    ("Backup", field("BACKUP_ES_REPOSITORY", "Elasticsearch snapshot repository")),
    ("Operasional", field("POLICY_POLL_SECONDS", "Interval sinkronisasi kebijakan (detik)", "number", default=60, minimum=10, maximum=3600)),
    ("Operasional", field("MASTER_CONFIG_POLL_SECONDS", "Interval sinkronisasi konfigurasi Master (detik)", "number", default=60, minimum=10, maximum=3600)),
    ("Operasional", field("ENGINE_CLAIM_IDLE_MS", "Waktu klaim ulang antrean engine (ms)", "number", default=60000, minimum=1000, maximum=3600000)),
]

CATALOG = {item["key"]: {"category": category, **item} for category, item in _FIELDS}
SECRET_KEYS = {key for key, item in CATALOG.items() if item["secret"]}
BOOTSTRAP_KEYS = {"MASTER_URL", "CLUSTER_ID", "MASTER_CLUSTER_TOKEN", "MASTER_POLICY_PUBKEY"}
_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_CONNECTOR_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def config_catalog() -> list[dict]:
    return [dict(item) for item in CATALOG.values()]


def _fernet() -> Fernet:
    path = os.getenv("MASTER_CONFIG_ENCRYPTION_KEY_FILE", "")
    if not path:
        raise RuntimeError("MASTER_CONFIG_ENCRYPTION_KEY_FILE wajib diset; kunci harus disimpan di luar database")
    try:
        key = Path(path).read_bytes().strip()
        return Fernet(key)
    except (OSError, ValueError) as exc:
        raise RuntimeError("kunci konfigurasi Master tidak tersedia atau formatnya tidak valid") from exc


def encrypt_config(config: dict) -> str:
    return _fernet().encrypt(json.dumps(config, sort_keys=True, separators=(",", ":")).encode()).decode()


def decrypt_config(token: str) -> dict:
    try:
        return json.loads(_fernet().decrypt(token.encode()))
    except InvalidToken as exc:
        raise RuntimeError("konfigurasi terenkripsi tidak dapat dibuka; periksa kunci enkripsi Master") from exc


def validate_config(body: dict) -> dict:
    if set(body) - {"settings", "secrets", "autoscaling", "connectors"}:
        raise ValueError("bagian konfigurasi tidak dikenal")
    settings = body.get("settings", {})
    secrets = body.get("secrets", {})
    if not isinstance(settings, dict) or set(settings) - (CATALOG.keys() - SECRET_KEYS):
        raise ValueError("ada setting non-secret yang tidak didukung")
    if not isinstance(secrets, dict) or set(secrets) - SECRET_KEYS:
        raise ValueError("ada nama secret yang tidak didukung")
    clean_settings = {}
    for key, value in settings.items():
        spec = CATALOG[key]
        kind = spec["kind"]
        if kind == "boolean":
            valid = isinstance(value, bool)
        elif kind == "number":
            valid = isinstance(value, (int, float)) and not isinstance(value, bool)
        elif kind == "json":
            try:
                json.loads(value)
                valid = isinstance(value, str)
            except (TypeError, ValueError):
                valid = False
        elif kind == "select":
            valid = isinstance(value, str) and value in spec["options"]
        else:
            valid = isinstance(value, str) and len(value) <= 4096
        if not valid:
            raise ValueError(f"nilai {key} tidak sesuai tipe")
        if kind == "number" and ((spec["minimum"] is not None and value < spec["minimum"]) or
                                 (spec["maximum"] is not None and value > spec["maximum"])):
            raise ValueError(f"nilai {key} di luar batas")
        if key in {"DATABASE_URL"}:
            if not value.startswith(("postgresql://", "postgresql+psycopg://")):
                raise ValueError("DATABASE_URL harus memakai PostgreSQL")
            parsed = urlparse(value)
            if not parsed.hostname or parsed.username is None or parsed.password is None:
                raise ValueError("DATABASE_URL harus berisi host dan kredensial")
            _ = parsed.port
        if key in {"ELASTICSEARCH_URL", "GLPI_URL", "OPENCTI_URL", "OLLAMA_URL", "LLM_BASE_URL"} and value:
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError(f"{key} harus berupa http(s) URL tanpa kredensial pada URL")
            _ = parsed.port
        if key == "ELASTICSEARCH_URL" and value and not value.startswith("https://"):
            raise ValueError("ELASTICSEARCH_URL production wajib menggunakan HTTPS")
        if key == "NEO4J_URI" and value:
            parsed = urlparse(value)
            if parsed.scheme not in {"neo4j", "neo4j+s", "neo4j+ssc", "bolt", "bolt+s", "bolt+ssc"} or not parsed.hostname:
                raise ValueError("NEO4J_URI harus memakai neo4j/bolt URI dengan host valid")
            if parsed.username or parsed.password:
                raise ValueError("kredensial Neo4j harus diatur terpisah dari NEO4J_URI")
            _ = parsed.port
        if key == "REDIS_URL" and value and not value.startswith(("redis://", "rediss://")):
            raise ValueError("REDIS_URL harus memakai redis:// atau rediss://")
        if key == "ELASTICSEARCH_INDEX" and value and not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,254}", value):
            raise ValueError("ELASTICSEARCH_INDEX berisi karakter yang tidak didukung")
        if key in {"ASSET_INVENTORY_FILE", "INTEL_FILE", "VULN_FILE", "KB_SEED_FILE",
                   "GLPI_CONFIG", "SCORING_CONFIG", "RULES_CONFIG"} and value and not Path(value).is_absolute():
            raise ValueError(f"{key} harus berupa path absolut")
        clean_settings[key] = value
    clean_secrets = {}
    for key, value in secrets.items():
        if not isinstance(value, str) or len(value) > 16384:
            raise ValueError(f"secret {key} tidak valid")
        if value:
            clean_secrets[key] = value
    autoscaling = body.get("autoscaling", {})
    if not isinstance(autoscaling, dict) or set(autoscaling) - {
        "enabled", "engine_min", "engine_max", "engine_lag_target", "api_min", "api_max", "api_cpu_target",
        "web_min", "web_max", "web_cpu_target",
    }:
        raise ValueError("pengaturan autoscaling tidak dikenal")
    defaults = {"enabled": False, "engine_min": 2, "engine_max": 10, "engine_lag_target": 100,
                "api_min": 3, "api_max": 10, "api_cpu_target": 70, "web_min": 2, "web_max": 6, "web_cpu_target": 70}
    scaling = defaults | autoscaling
    for key, value in scaling.items():
        if key == "enabled":
            if not isinstance(value, bool):
                raise ValueError("autoscaling.enabled harus boolean")
        elif not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"autoscaling.{key} harus bilangan bulat")
        elif not 1 <= value <= (1000 if key.endswith("_max") else 10000):
            raise ValueError(f"autoscaling.{key} di luar batas")
    for component in ("engine", "api", "web"):
        if scaling[f"{component}_min"] > scaling[f"{component}_max"]:
            raise ValueError(f"autoscaling.{component}_min tidak boleh lebih besar dari max")
    for component in ("api", "web"):
        target = scaling[f"{component}_cpu_target"]
        if not 10 <= target <= 95:
            raise ValueError(f"autoscaling.{component}_cpu_target harus 10..95")
    if scaling["enabled"] and (settings.get("INGEST_MODE") != "queue" or not secrets.get("REDIS_URL")):
        raise ValueError("autoscaling membutuhkan INGEST_MODE=queue dan REDIS_URL")
    for key, value in clean_secrets.items():
        if key == "DATABASE_URL":
            if not value.startswith(("postgresql://", "postgresql+psycopg://")):
                raise ValueError("DATABASE_URL harus memakai PostgreSQL")
            parsed = urlparse(value)
            if not parsed.hostname or parsed.username is None or parsed.password is None:
                raise ValueError("DATABASE_URL harus berisi host dan kredensial")
            _ = parsed.port
        elif key == "REDIS_URL" and value:
            parsed = urlparse(value)
            if (parsed.scheme not in {"redis", "rediss"} or not parsed.hostname or
                    (parsed.path not in {"", "/"} and not parsed.path[1:].isdigit())):
                raise ValueError("REDIS_URL harus memakai redis:// atau rediss:// dengan host valid")
            _ = parsed.port
    if "BACKUP_SCHEDULE_CRON" in clean_settings:
        from croniter import croniter
        cron = clean_settings["BACKUP_SCHEDULE_CRON"]
        if len(cron.split()) != 5 or not croniter.is_valid(cron):
            raise ValueError("BACKUP_SCHEDULE_CRON harus berupa ekspresi cron 5 kolom yang valid")
    if "BACKUP_TIMEZONE" in clean_settings:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        try:
            ZoneInfo(clean_settings["BACKUP_TIMEZONE"])
        except (ZoneInfoNotFoundError, ValueError) as exc:
            raise ValueError("BACKUP_TIMEZONE tidak dikenal") from exc
    if clean_settings.get("BACKUP_SCHEDULE_MODE", "cron") != "cron":
        raise ValueError("BACKUP_SCHEDULE_MODE hanya mendukung cron")
    if "BACKUP_REPOSITORY_URI" in clean_settings and clean_settings["BACKUP_REPOSITORY_URI"] and not Path(clean_settings["BACKUP_REPOSITORY_URI"]).is_absolute():
        raise ValueError("BACKUP_REPOSITORY_URI harus path absolut")
    if "BACKUP_COMPONENTS" in clean_settings:
        allowed_components = {"postgres", "sql", "sqlite", "redis", "neo4j", "elasticsearch"}
        components = [item.strip() for item in clean_settings["BACKUP_COMPONENTS"].split(",") if item.strip()]
        if not components or set(components) - allowed_components or len(components) != len(set(components)):
            raise ValueError("BACKUP_COMPONENTS kosong, duplikat, atau berisi komponen yang tidak didukung")
    if clean_settings.get("BACKUP_ENABLED") and not clean_secrets.get("BACKUP_ENCRYPTION_KEY"):
        raise ValueError("backup aktif memerlukan BACKUP_ENCRYPTION_KEY")
    connectors = body.get("connectors", [])
    if not isinstance(connectors, list) or len(connectors) > 100:
        raise ValueError("connectors harus berupa daftar maksimal 100 item")
    clean_connectors = []
    connector_names = set()
    for connector in connectors:
        if not isinstance(connector, dict) or set(connector) - {
            "name", "type", "enabled", "tenant_id", "poll_seconds", "batch_size", "initial_lookback_hours", "params",
        }:
            raise ValueError("format konektor tidak valid")
        kind = connector.get("type")
        name = connector.get("name")
        if not isinstance(kind, str) or kind not in CONNECTOR_CATALOG or not isinstance(name, str) or not _CONNECTOR_NAME.fullmatch(name):
            raise ValueError("nama atau tipe konektor tidak valid")
        if name in connector_names:
            raise ValueError("nama konektor harus unik pada cluster")
        connector_names.add(name)
        tenant_id = connector.get("tenant_id", "default")
        if not isinstance(tenant_id, str) or tenant_id not in {"default", "*"}:
            raise ValueError("tenant konektor pada konfigurasi cluster harus default atau *")
        enabled = connector.get("enabled", False)
        if not isinstance(enabled, bool):
            raise ValueError(f"enabled konektor {name} harus boolean")
        params = connector.get("params", {})
        if not isinstance(params, dict):
            raise ValueError("params konektor harus berupa object")
        fields = {item["key"]: item for item in CONNECTOR_CATALOG[kind]["fields"]}
        if set(params) - fields.keys():
            raise ValueError(f"parameter konektor {name} tidak dikenal")
        clean_params = {}
        for key, field_spec in fields.items():
            value = params.get(key, field_spec.get("default"))
            if value is None or value == "":
                if field_spec["required"]:
                    raise ValueError(f"konektor {name} memerlukan {field_spec['label']}")
                continue
            field_kind = field_spec["kind"]
            if field_kind == "boolean":
                valid = isinstance(value, bool)
            elif field_kind == "number":
                valid = isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 10000
            elif field_kind == "select":
                valid = isinstance(value, str) and value in field_spec["options"]
            else:
                valid = isinstance(value, str) and len(value) <= 2048
            if not valid:
                raise ValueError(f"parameter {key} pada konektor {name} tidak valid")
            if field_kind == "secret_ref":
                if not _ENV_NAME.fullmatch(value):
                    raise ValueError(f"{key} konektor {name} harus berupa nama environment variable")
                if enabled and value not in clean_secrets:
                    raise ValueError(f"secret {value} untuk konektor {name} belum dikonfigurasi")
            if key == "base_url":
                parsed = urlparse(value)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                    raise ValueError(f"base_url konektor {name} harus http(s) URL tanpa kredensial")
                _ = parsed.port
            clean_params[key] = value
        poll_seconds = connector.get("poll_seconds", 60)
        batch_size = connector.get("batch_size", 500)
        lookback = connector.get("initial_lookback_hours", 24)
        if not isinstance(poll_seconds, int) or isinstance(poll_seconds, bool) or not 10 <= poll_seconds <= 86400:
            raise ValueError(f"poll_seconds konektor {name} di luar batas")
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or not 1 <= batch_size <= 10000:
            raise ValueError(f"batch_size konektor {name} di luar batas")
        if not isinstance(lookback, int) or isinstance(lookback, bool) or not 1 <= lookback <= 8760:
            raise ValueError(f"initial_lookback_hours konektor {name} di luar batas")
        clean_connectors.append({
            "name": connector["name"], "type": kind, "tenant_id": "default",
            "enabled": enabled,
            "poll_seconds": poll_seconds,
            "batch_size": batch_size,
            "initial_lookback_hours": lookback,
            "params": clean_params,
        })
    return {"settings": clean_settings, "secrets": clean_secrets, "autoscaling": scaling, "connectors": clean_connectors}


def public_config(config: dict) -> dict:
    return {
        "settings": config.get("settings", {}),
        "secrets_set": sorted(config.get("secrets", {}).keys()),
        "autoscaling": config.get("autoscaling", {}),
        "connectors": config.get("connectors", []),
    }


def config_environment(config: dict) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Split UI settings into ConfigMap, runtime Secret and connector Secret values."""
    data: dict[str, str] = {}
    runtime: dict[str, str] = {}
    connectors: dict[str, str] = {}
    for key, value in config.get("settings", {}).items():
        data[key] = json.dumps(value, separators=(",", ":")) if isinstance(value, (dict, list)) else str(value)
    for key, value in config.get("secrets", {}).items():
        if key in {"SPLUNK_TOKEN", "SENTINEL_CLIENT_SECRET", "QRADAR_TOKEN", "CS_CLIENT_SECRET", "S1_API_TOKEN",
                   "DEFENDER_CLIENT_SECRET", "CORTEX_API_KEY", "WAZUH_INDEXER_PASSWORD", "ELASTIC_API_KEY"}:
            connectors[key] = value
        else:
            runtime[key] = value
    return data, runtime, connectors
