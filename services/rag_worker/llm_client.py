"""JSON-generating clients for Ollama, Gemini, and OpenAI-compatible APIs."""
from __future__ import annotations

import json
from typing import Protocol
from urllib.parse import quote

import httpx


DEFAULT_OPENAI_URL = "https://api.openai.com/v1"
DEFAULT_GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta"


class LLMClient(Protocol):
    model: str

    def generate_json(self, system: str, user: str) -> dict: ...


def _json_object(text: str) -> dict:
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("respons AI harus berupa objek JSON")
    return value


class _HTTPClient:
    def __init__(self, timeout: float, transport: httpx.BaseTransport | None = None):
        self.timeout = timeout
        self.transport = transport

    def _post(self, url: str, *, headers: dict[str, str] | None = None, json_body: dict) -> httpx.Response:
        with httpx.Client(timeout=self.timeout, transport=self.transport) as client:
            response = client.post(url, headers=headers, json=json_body)
        response.raise_for_status()
        return response


class OllamaClient(_HTTPClient):
    def __init__(self, url: str, model: str, timeout: float, transport: httpx.BaseTransport | None = None):
        super().__init__(timeout, transport)
        self.url, self.model = url.rstrip("/"), model

    def generate_json(self, system: str, user: str) -> dict:
        response = self._post(f"{self.url}/api/chat", json_body={
            "model": self.model, "stream": False, "format": "json", "options": {"temperature": 0},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        })
        return _json_object(response.json()["message"]["content"])


class OpenAICompatibleClient(_HTTPClient):
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str,
        timeout: float,
        transport: httpx.BaseTransport | None = None,
    ):
        super().__init__(timeout, transport)
        if not base_url:
            raise ValueError("LLM_BASE_URL wajib diisi untuk provider OpenAI-compatible")
        if not model:
            raise ValueError("LLM_MODEL wajib diisi untuk provider OpenAI-compatible")
        self.url = self._completion_url(base_url)
        self.model = model
        self.api_key = api_key

    @staticmethod
    def _completion_url(base_url: str) -> str:
        base = base_url.rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        if base.endswith("/v1"):
            return f"{base}/chat/completions"
        return f"{base}/v1/chat/completions"

    def generate_json(self, system: str, user: str) -> dict:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        response = self._post(self.url, headers=headers, json_body={
            "model": self.model,
            "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        })
        content = response.json()["choices"][0]["message"]["content"]
        if isinstance(content, list):
            content = "".join(part.get("text", "") for part in content if isinstance(part, dict))
        if not isinstance(content, str):
            raise ValueError("format respons OpenAI-compatible tidak didukung")
        return _json_object(content)


class OpenAIClient(OpenAICompatibleClient):
    def __init__(
        self,
        model: str,
        api_key: str,
        timeout: float,
        base_url: str = "https://api.openai.com/v1",
        transport: httpx.BaseTransport | None = None,
    ):
        if not api_key:
            raise ValueError("LLM_API_KEY wajib diisi untuk OpenAI")
        super().__init__(base_url, model, api_key, timeout, transport)


class GeminiClient(_HTTPClient):
    def __init__(
        self,
        model: str,
        api_key: str,
        timeout: float,
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
        transport: httpx.BaseTransport | None = None,
    ):
        super().__init__(timeout, transport)
        if not api_key:
            raise ValueError("LLM_API_KEY wajib diisi untuk Gemini")
        if not model:
            raise ValueError("LLM_MODEL wajib diisi untuk Gemini")
        self.url = f"{base_url.rstrip('/')}/models/{quote(model, safe='')}:generateContent"
        self.model = model
        self.api_key = api_key

    def generate_json(self, system: str, user: str) -> dict:
        response = self._post(
            self.url,
            headers={"x-goog-api-key": self.api_key},
            json_body={
                "systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {"responseMimeType": "application/json", "temperature": 0},
            },
        )
        parts = response.json()["candidates"][0]["content"]["parts"]
        content = "".join(part.get("text", "") for part in parts if isinstance(part, dict))
        return _json_object(content)


def create_llm_client(settings) -> LLMClient | None:
    """Resolve the configured provider; auto preserves the previous Ollama behavior."""
    provider = settings.llm_provider
    if provider == "auto":
        if settings.ollama_url and settings.ollama_model:
            provider = "ollama"
        else:
            return None
    if provider == "none":
        return None
    if provider == "ollama":
        if not (settings.ollama_url and settings.ollama_model):
            raise ValueError("OLLAMA_URL dan OLLAMA_MODEL wajib diisi untuk Ollama")
        return OllamaClient(settings.ollama_url, settings.ollama_model, settings.ollama_timeout)
    if provider == "openai":
        return OpenAIClient(
            settings.llm_model,
            settings.llm_api_key,
            settings.llm_timeout,
            settings.llm_base_url or DEFAULT_OPENAI_URL,
        )
    if provider == "gemini":
        return GeminiClient(
            settings.llm_model,
            settings.llm_api_key,
            settings.llm_timeout,
            settings.llm_base_url or DEFAULT_GEMINI_URL,
        )
    if provider == "openai_compatible":
        return OpenAICompatibleClient(
            settings.llm_base_url,
            settings.llm_model,
            settings.llm_api_key,
            settings.llm_timeout,
        )
    raise ValueError("LLM_PROVIDER harus auto, none, ollama, openai, gemini, atau openai_compatible")
