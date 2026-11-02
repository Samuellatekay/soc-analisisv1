"""Read/write smoke tests for configured staging data services.

Run inside the Compose network with:
docker compose run --rm --no-deps -v ../scripts:/app/scripts:ro api \
    python /app/scripts/staging_smoke.py --only elasticsearch,neo4j
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid
from urllib.parse import urlsplit

from services.common.config import get_settings

SERVICES = {"elasticsearch", "neo4j", "ollama", "opencti"}


def _require_http_url(value: str, name: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{name} must be an absolute HTTP(S) URL")


def check_elasticsearch(settings) -> None:
    if not settings.es_url:
        print("Elasticsearch: SKIP (ELASTICSEARCH_URL not configured)")
        return
    _require_http_url(settings.es_url, "ELASTICSEARCH_URL")
    from services.indexer.elasticsearch_client import ESClient

    index = f"soc-integration-smoke-{uuid.uuid4().hex}"
    client = ESClient(settings.es_url, index, api_key=settings.es_api_key)
    try:
        client.ensure_index()
        document_id = str(uuid.uuid4())
        client.upsert(document_id, {
            "event_id": document_id,
            "tenant_id": "integration-smoke",
            "source": "staging-smoke",
            "event_time": "2026-01-01T00:00:00Z",
            "received_at": "2026-01-01T00:00:00Z",
            "severity": "low",
            "attack_type": "integration-smoke",
            "risk_score": 0.0,
            "risk_level": "low",
            "disposition": "retained",
            "processing_status": "indexed",
            "analysis_status": "not_requested",
            "technique_id": "T0000",
            "src_ip": "192.0.2.1",
            "dst_ip": "198.51.100.1",
            "host": "integration-smoke.invalid",
            "message": "staging integration smoke test",
            "signature": "staging integration smoke test",
        })
        client.http.post(f"{client.url}/{index}/_refresh").raise_for_status()
        result = client.search({"query": {"term": {"event_id": document_id}}, "size": 1})
        hits = result.get("hits", {}).get("hits", [])
        if not hits or hits[0].get("_id") != document_id:
            raise RuntimeError("Elasticsearch smoke document was not searchable")
        print("Elasticsearch: PASS (mapping, upsert, and search)")
    finally:
        try:
            client.http.delete(f"{client.url}/{index}").raise_for_status()
        finally:
            client.http.close()


def check_neo4j(settings) -> None:
    if not settings.neo4j_uri or not settings.neo4j_password:
        print("Neo4j: SKIP (NEO4J_URI or password not configured)")
        return
    from services.rag_worker.retrieval.graph import Neo4jRetriever

    suffix = uuid.uuid4().hex
    technique_id = f"SOC_SMOKE_{suffix}"
    tactic_name = f"SOC_SMOKE_{suffix}"
    playbook_id = f"SOC_SMOKE_{suffix}"
    tenant_id = f"soc-smoke-{suffix}"
    retriever = Neo4jRetriever(settings)
    try:
        with retriever.driver.session() as session:
            session.run(
                "CREATE (t:Technique {id:$id, name:$name, description:$description, "
                "source:$source, version:$version, access_tenants:$tenants, updated_at_epoch:$updated}) "
                "CREATE (ta:Tactic {name:$tactic}) CREATE (t)-[:IN_TACTIC]->(ta) "
                "CREATE (:Playbook {id:$playbook_id, attack_type:$attack_type, title:$title, "
                "steps:$steps, source:$source, version:$version, access_tenants:$tenants, updated_at_epoch:$updated})",
                id=technique_id, name="Smoke test technique", description="temporary",
                source="staging-smoke", version="1", tenants=[tenant_id],
                updated=time.time(), tactic=tactic_name, playbook_id=playbook_id,
                attack_type=f"soc-smoke-{suffix}", title="Smoke test playbook", steps=["temporary"],
            ).consume()
        docs = retriever.retrieve(tenant_id, technique_id, f"soc-smoke-{suffix}", tactic_name)
        if not any(d.source_id == technique_id and tactic_name in d.text for d in docs):
            raise RuntimeError("Neo4j retriever query did not return the test graph")
        if not any(d.source_id == playbook_id for d in docs):
            raise RuntimeError("Neo4j playbook query did not return the test graph")
        if retriever.retrieve(f"{tenant_id}-other", technique_id, f"soc-smoke-{suffix}", tactic_name):
            raise RuntimeError("Neo4j retriever exposed a tenant-scoped test node")
        print("Neo4j: PASS (schema, parameterized Cypher retrieval, freshness, and tenant filter)")
    finally:
        try:
            with retriever.driver.session() as session:
                session.run(
                    "MATCH (n) WHERE n.id IN $ids OR (n:Tactic AND n.name=$tactic) "
                    "DETACH DELETE n",
                    ids=[technique_id, playbook_id], tactic=tactic_name,
                ).consume()
        finally:
            retriever.driver.close()


def check_ollama(settings) -> None:
    if not settings.ollama_url or not settings.ollama_model:
        print("Ollama: SKIP (OLLAMA_URL or OLLAMA_MODEL not configured)")
        return
    _require_http_url(settings.ollama_url, "OLLAMA_URL")
    import json
    import httpx

    response = httpx.get(f"{settings.ollama_url.rstrip('/')}/api/tags", timeout=5)
    response.raise_for_status()
    models = {item.get("name") for item in response.json().get("models", [])}
    if settings.ollama_model not in models:
        raise RuntimeError("Configured Ollama model is not installed")
    from services.rag_worker.llm_client import OllamaClient

    result = OllamaClient(settings.ollama_url, settings.ollama_model, settings.ollama_timeout).generate_json(
        "Return only the requested JSON.",
        'Return {"status":"ok"}.',
    )
    if result.get("status") != "ok":
        raise RuntimeError("Ollama JSON generation smoke test failed")
    print("Ollama: PASS (model availability and JSON chat generation)")


def check_opencti(settings) -> None:
    if not settings.opencti_url or not settings.opencti_token:
        print("OpenCTI: SKIP (OPENCTI_URL or token not configured)")
        return
    _require_http_url(settings.opencti_url, "OPENCTI_URL")
    from services.engine.enrichment.providers import OpenCTIProvider

    provider = OpenCTIProvider(settings.opencti_url, settings.opencti_token, settings.enrichment_timeout)
    provider.lookup("198.51.100.1")
    print("OpenCTI: PASS (authenticated GraphQL indicator query)")


CHECKS = {
    "elasticsearch": check_elasticsearch,
    "neo4j": check_neo4j,
    "ollama": check_ollama,
    "opencti": check_opencti,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", help=f"comma-separated services to check: {', '.join(sorted(SERVICES))}")
    args = parser.parse_args()
    selected = set(args.only.split(",")) if args.only else SERVICES
    unknown = selected - SERVICES
    if unknown or not selected:
        parser.error(f"unknown or empty service selection: {', '.join(sorted(unknown))}")

    settings = get_settings()
    failures = 0
    for service in sorted(selected):
        try:
            CHECKS[service](settings)
        except Exception as error:
            failures += 1
            print(f"{service}: FAIL ({type(error).__name__})", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
