"""Parameter yang dapat dikonfigurasi untuk setiap konektor."""

def _field(key: str, label: str, kind: str = "text", required: bool = False, default=None, help: str = "", options=None) -> dict:
    return {"key": key, "label": label, "kind": kind, "required": required, "default": default, "help": help, "options": options or []}


_BASE_URL = _field("base_url", "URL layanan", required=True, help="Gunakan https:// untuk koneksi produksi.")
_VERIFY_TLS = _field("verify_tls", "Verifikasi TLS", "boolean", default=True)
_OVERLAP = _field("overlap_seconds", "Overlap cursor (detik)", "number", default=120)

CATALOG = {
    "splunk_es": {
        "label": "Splunk Enterprise Security",
        "fields": [_BASE_URL, _field("token_env", "Nama environment token", "secret_ref", True),
                   _field("index", "Index", default="notable"), _field("event_window", "Rentang pencarian", default="-7d"),
                   _VERIFY_TLS, _OVERLAP],
    },
    "sentinel": {
        "label": "Microsoft Sentinel",
        "fields": [_field("tenant_id", "Tenant ID", required=True), _field("client_id", "Client ID", required=True),
                   _field("client_secret_env", "Nama environment client secret", "secret_ref", True),
                   _field("subscription_id", "Subscription ID", required=True), _field("resource_group", "Resource group", required=True),
                   _field("workspace", "Workspace", required=True), _field("fetch_entities", "Ambil entitas", "boolean", default=True),
                   _field("max_pages", "Maksimum halaman", "number", default=20), _OVERLAP],
    },
    "qradar": {
        "label": "IBM QRadar",
        "fields": [_BASE_URL, _field("token_env", "Nama environment token", "secret_ref", True),
                   _field("api_version", "Versi API", default="19.0"), _VERIFY_TLS, _OVERLAP],
    },
    "crowdstrike": {
        "label": "CrowdStrike Falcon",
        "fields": [_field("base_url", "URL layanan", default="https://api.crowdstrike.com"),
                   _field("client_id", "Client ID", required=True),
                   _field("client_secret_env", "Nama environment client secret", "secret_ref", True),
                   _field("fql_extra", "Filter FQL tambahan"), _OVERLAP],
    },
    "sentinelone": {
        "label": "SentinelOne",
        "fields": [_BASE_URL, _field("token_env", "Nama environment token", "secret_ref", True),
                   _field("time_field", "Field waktu", default="createdAt"), _field("max_pages", "Maksimum halaman", "number", default=20), _OVERLAP],
    },
    "defender": {
        "label": "Microsoft Defender",
        "fields": [_field("tenant_id", "Tenant ID", required=True), _field("client_id", "Client ID", required=True),
                   _field("client_secret_env", "Nama environment client secret", "secret_ref", True),
                   _field("max_pages", "Maksimum halaman", "number", default=50), _OVERLAP],
    },
    "cortex_xdr": {
        "label": "Palo Alto Cortex XDR",
        "fields": [_BASE_URL, _field("key_id", "API key ID", required=True),
                   _field("key_env", "Nama environment API key", "secret_ref", True),
                   _field("auth_type", "Tipe autentikasi", "select", default="standard", help="Pilih standard atau advanced.", options=["standard", "advanced"]),
                   _field("alerts_path", "Path API alert"), _OVERLAP],
    },
    "elasticsearch": {
        "label": "Elasticsearch / Wazuh",
        "fields": [_BASE_URL, _field("index", "Index/pattern", required=True),
                   _field("time_field", "Field waktu", default="@timestamp"),
                   _field("mapper", "Mapper", "select", default="ecs", help="Pilih ecs atau wazuh.", options=["ecs", "wazuh"]),
                   _field("username", "Username"),
                   _field("password_env", "Nama environment password", "secret_ref"),
                   _field("api_key_env", "Nama environment API key", "secret_ref"),
                   _field("verify_tls", "Verifikasi TLS", "boolean", default=True),
                   _field("sort_by_id", "Urutkan berdasarkan ID", "boolean", default=False), _OVERLAP],
    },
}


def catalog_response() -> dict:
    """Return copyable metadata safe for the UI."""
    return {
        name: {"label": item["label"], "fields": [dict(field) for field in item["fields"]]}
        for name, item in CATALOG.items()
    }
