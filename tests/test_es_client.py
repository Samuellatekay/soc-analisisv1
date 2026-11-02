import httpx

from services.indexer.elasticsearch_client import ESClient


def test_es_client_sends_api_key_in_authorization_header():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"result": "created"})

    client = ESClient(
        "https://es.example.com",
        "soc-alerts",
        api_key="encoded-api-key",
        transport=httpx.MockTransport(handler),
    )
    try:
        client.upsert("event-1", {"event_id": "event-1"})
    finally:
        client.http.close()

    assert len(seen) == 1
    assert seen[0].headers["Authorization"] == "ApiKey encoded-api-key"
    assert "encoded-api-key" not in str(seen[0].url)


def test_es_client_keeps_auth_optional_for_local_development():
    client = ESClient("http://localhost:9200", "soc-alerts")
    try:
        assert "Authorization" not in client.http.headers
    finally:
        client.http.close()
