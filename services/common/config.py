"""Konfigurasi dari environment. Tidak ada secret yang di-hardcode."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _b(name: str, default: bool) -> bool:
    v = os.getenv(name)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "on"}


def read_secret(name: str) -> str:
    return _read_secret(name)


def _read_secret(name: str) -> str:
    """Baca nilai dari NAME atau dari file NAME_FILE (Docker secrets)."""
    f = os.getenv(f"{name}_FILE")
    if f and Path(f).exists():
        return Path(f).read_text().strip()
    return os.getenv(name, "")


@dataclass
class Settings:
    database_url: str = field(default_factory=lambda: os.getenv("DATABASE_URL", f"sqlite:///{ROOT / 'data' / 'soc.db'}"))
    redis_url: str = field(default_factory=lambda: os.getenv("REDIS_URL", ""))
    es_url: str = field(default_factory=lambda: os.getenv("ELASTICSEARCH_URL", ""))
    es_index: str = field(default_factory=lambda: os.getenv("ELASTICSEARCH_INDEX", "soc-alerts-v1"))
    neo4j_uri: str = field(default_factory=lambda: os.getenv("NEO4J_URI", ""))
    neo4j_user: str = field(default_factory=lambda: os.getenv("NEO4J_USER", "neo4j"))
    neo4j_password: str = field(default_factory=lambda: _read_secret("NEO4J_PASSWORD"))
    ollama_url: str = field(default_factory=lambda: os.getenv("OLLAMA_URL", ""))
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", ""))
    ollama_timeout: float = field(default_factory=lambda: float(os.getenv("OLLAMA_TIMEOUT", "60")))
    prompt_version: str = field(default_factory=lambda: os.getenv("PROMPT_VERSION", "analysis_v1"))
    bert_model_path: str = field(default_factory=lambda: os.getenv("BERT_MODEL_PATH", ""))
    opencti_url: str = field(default_factory=lambda: os.getenv("OPENCTI_URL", ""))
    opencti_token: str = field(default_factory=lambda: _read_secret("OPENCTI_TOKEN"))
    inventory_file: str = field(default_factory=lambda: os.getenv("ASSET_INVENTORY_FILE", str(ROOT / "data" / "assets.json")))
    intel_file: str = field(default_factory=lambda: os.getenv("INTEL_FILE", str(ROOT / "data" / "intel.json")))
    glpi_url: str = field(default_factory=lambda: os.getenv("GLPI_URL", ""))
    glpi_app_token: str = field(default_factory=lambda: _read_secret("GLPI_APP_TOKEN"))
    glpi_user_token: str = field(default_factory=lambda: _read_secret("GLPI_USER_TOKEN"))
    glpi_config: str = field(default_factory=lambda: os.getenv("GLPI_CONFIG", str(ROOT / "infra" / "config" / "glpi.json")))
    glpi_insecure_tls: bool = field(default_factory=lambda: _b("GLPI_INSECURE_TLS", False))
    vuln_file: str = field(default_factory=lambda: os.getenv("VULN_FILE", str(ROOT / "data" / "vulns.json")))
    kb_seed_file: str = field(default_factory=lambda: os.getenv("KB_SEED_FILE", str(ROOT / "data" / "kb_seed.json")))
    scoring_config: str = field(default_factory=lambda: os.getenv("SCORING_CONFIG", str(ROOT / "infra" / "config" / "scoring_v1.json")))
    rules_config: str = field(default_factory=lambda: os.getenv("RULES_CONFIG", str(ROOT / "infra" / "config" / "rules.json")))
    enrichment_timeout: float = field(default_factory=lambda: float(os.getenv("ENRICHMENT_TIMEOUT", "2.0")))
    enrichment_cache_ttl: int = field(default_factory=lambda: int(os.getenv("ENRICHMENT_CACHE_TTL", "300")))
    # noise reduction
    fft_min_history_hours: int = field(default_factory=lambda: int(os.getenv("FFT_MIN_HISTORY_HOURS", "48")))
    fft_peak_ratio: float = field(default_factory=lambda: float(os.getenv("FFT_PEAK_RATIO", "3.0")))
    pcc_threshold: float = field(default_factory=lambda: float(os.getenv("PCC_THRESHOLD", "0.85")))
    # fusion
    fusion_retain: float = 0.60
    fusion_filter: float = 0.30
    # auth: "token1:admin:default,token2:analyst:default"
    api_tokens: str = field(default_factory=lambda: _read_secret("API_TOKENS"))
    ingest_key: str = field(default_factory=lambda: _read_secret("INGEST_API_KEY"))
    ingest_mode: str = field(default_factory=lambda: os.getenv("INGEST_MODE", "inline"))  # inline | queue
    embedded_workers: bool = field(default_factory=lambda: _b("EMBEDDED_WORKERS", True))
    env_industry_campaign: bool = field(default_factory=lambda: _b("ENV_INDUSTRY_CAMPAIGN", False))
    env_network_anomaly: bool = field(default_factory=lambda: _b("ENV_NETWORK_WIDE_ANOMALY", False))
    kb_sync_cron_hour: int = field(default_factory=lambda: int(os.getenv("KB_SYNC_HOUR", "1")))
    kb_sync_tz: str = field(default_factory=lambda: os.getenv("KB_SYNC_TZ", "Asia/Jakarta"))
    kb_stale_days: int = field(default_factory=lambda: int(os.getenv("KB_STALE_DAYS", "3")))
    connectors_config: str = field(default_factory=lambda: os.getenv("CONNECTORS_CONFIG", str(ROOT / "infra" / "config" / "connectors.json")))
    embedded_connectors: bool = field(default_factory=lambda: _b("EMBEDDED_CONNECTORS", True))
    max_payload_bytes: int = field(default_factory=lambda: int(os.getenv("MAX_PAYLOAD_BYTES", "262144")))

    def scoring(self) -> dict:
        return json.loads(Path(self.scoring_config).read_text())

    def rules(self) -> dict:
        return json.loads(Path(self.rules_config).read_text())


@lru_cache
def get_settings() -> Settings:
    return Settings()
