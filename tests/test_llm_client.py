from types import SimpleNamespace

import httpx
import pytest

from services.rag_worker.llm_client import (
    GeminiClient,
    OllamaClient,
    OpenAIClient,
    OpenAICompatibleClient,
    create_llm_client,
)


def _transport(handler):
    return httpx.MockTransport(handler)


def test_gemini_uses_api_key_header_and_json_generation():
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["key"] = request.headers.get("x-goog-api-key")
        seen["body"] = request.read().decode()
        return httpx.Response(200, json={
            "candidates": [{"content": {"parts": [{"text": '{"summary":"ok"}'}]}}],
        })

    result = GeminiClient("gemini-test", "secret-key", 5, transport=_transport(handler)).generate_json("system", "user")

    assert result == {"summary": "ok"}
    assert seen["url"].endswith("/models/gemini-test:generateContent")
    assert "secret-key" not in seen["url"]
    assert seen["key"] == "secret-key"
    assert '"responseMimeType":"application/json"' in seen["body"]


@pytest.mark.parametrize(
    ("base_url", "expected_url"),
    [
        ("https://api.openai.com/v1", "https://api.openai.com/v1/chat/completions"),
        ("http://localhost:1234/v1/", "http://localhost:1234/v1/chat/completions"),
        ("https://provider.example/api/chat/completions", "https://provider.example/api/chat/completions"),
    ],
)
def test_openai_compatible_posts_json_chat_completion(base_url, expected_url):
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("Authorization")
        seen["body"] = request.read().decode()
        return httpx.Response(200, json={
            "choices": [{"message": {"content": '{"summary":"ok"}'}}],
        })

    result = OpenAICompatibleClient(
        base_url, "test-model", "secret-key", 5, transport=_transport(handler)
    ).generate_json("system", "user")

    assert result == {"summary": "ok"}
    assert seen["url"] == expected_url
    assert seen["auth"] == "Bearer secret-key"
    assert "secret-key" not in seen["url"]
    assert '"response_format":{"type":"json_object"}' in seen["body"]


def test_openai_uses_default_api_endpoint():
    client = OpenAIClient("gpt-test", "secret-key", 5, transport=_transport(
        lambda request: httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})
    ))
    assert client.url == "https://api.openai.com/v1/chat/completions"


def test_ollama_remains_supported():
    client = OllamaClient("http://ollama:11434/", "local-model", 5, transport=_transport(
        lambda request: httpx.Response(200, json={"message": {"content": '{"summary":"ok"}'}})
    ))
    assert client.generate_json("system", "user") == {"summary": "ok"}


def test_provider_factory_preserves_auto_ollama_and_template_defaults():
    settings = SimpleNamespace(
        llm_provider="auto", ollama_url="http://ollama:11434", ollama_model="local-model",
        ollama_timeout=10, llm_model="", llm_api_key="", llm_base_url="", llm_timeout=10,
    )
    assert isinstance(create_llm_client(settings), OllamaClient)
    settings.ollama_url = ""
    settings.ollama_model = ""
    assert create_llm_client(settings) is None


@pytest.mark.parametrize("provider", ["openai", "gemini", "openai_compatible"])
def test_provider_factory_requires_provider_configuration(provider):
    settings = SimpleNamespace(
        llm_provider=provider, ollama_url="", ollama_model="", ollama_timeout=10,
        llm_model="", llm_api_key="", llm_base_url="", llm_timeout=10,
    )
    with pytest.raises(ValueError):
        create_llm_client(settings)


def test_non_object_json_response_is_rejected():
    client = OllamaClient("http://ollama:11434", "local-model", 5, transport=_transport(
        lambda request: httpx.Response(200, json={"message": {"content": '["not", "an", "object"]'}})
    ))
    with pytest.raises(ValueError, match="objek JSON"):
        client.generate_json("system", "user")
