import httpx
import pytest

from services.engine.enrichment.providers import OpenCTIProvider


def test_opencti_graphql_response_is_mapped_to_ioc_fact(monkeypatch):
    seen = {}

    def post(url, *, json, headers, timeout):
        seen.update(url=url, query=json["query"], variables=json["variables"], headers=headers, timeout=timeout)
        return httpx.Response(200, request=httpx.Request("POST", url), json={"data": {"indicators": {"edges": [{"node": {
            "confidence": 90, "x_opencti_score": 80, "updated_at": "2026-11-01T00:00:00Z",
        }}]}}})

    monkeypatch.setattr(httpx, "post", post)
    facts = OpenCTIProvider("https://opencti.example", "token-value", 2).lookup("203.0.113.8")
    assert len(facts) == 1
    assert (facts[0].subj_type, facts[0].subj_id, facts[0].pred, facts[0].value) == (
        "IOC", "203.0.113.8", "verdict", "malicious")
    assert facts[0].confidence == 0.9
    assert seen["url"] == "https://opencti.example/graphql"
    assert seen["variables"] == {"s": "203.0.113.8"}
    assert seen["headers"]["Authorization"]
    assert "valid_until" not in seen["query"]


@pytest.mark.parametrize("body", [
    {"errors": [{"message": "unknown field"}]},
    {"data": {"indicators": None}},
    {"data": {"indicators": {"edges": [{"node": None}]}}},
])
def test_opencti_graphql_errors_and_unexpected_shapes_fail_loudly(monkeypatch, body):
    monkeypatch.setattr(httpx, "post", lambda url, **_kwargs: httpx.Response(
        200, request=httpx.Request("POST", url), json=body))
    with pytest.raises(RuntimeError, match="OpenCTI GraphQL"):
        OpenCTIProvider("https://opencti.example", "token-value", 2).lookup("203.0.113.8")
