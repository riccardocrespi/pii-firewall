import os
from typing import Protocol, List, Literal, Dict, Any

import httpx

from .errors import FirewallError


ProviderName = Literal["openai", "anthropic", "google", "deepseek"]


class ProviderClient(Protocol):
    async def chat(self, messages: List[Dict[str, str]]) -> str:
        """
        Accepts a list of messages [{"role": "...", "content": "..."}]
        and returns the assistant's reply text.
        """
        ...


class OpenAIClient:
    """
    Minimal wrapper for OpenAI Chat Completions API (gpt-4.x / gpt-3.5-like).

    We assume:
      - API key in OPENAI_API_KEY
      - Model name in OPENAI_MODEL (default: gpt-4o-mini)
    """

    def __init__(self) -> None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise FirewallError("OPENAI_API_KEY is not set")

        self._api_key = api_key
        self._model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self._base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

    async def chat(self, messages: List[Dict[str, str]]) -> str:
        url = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
        }
        payload = {
            "model": self._model,
            "messages": messages,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code >= 400:
                raise FirewallError(f"OpenAI API error: {resp.status_code} {resp.text}")

            data = resp.json()
            try:
                return data["choices"][0]["message"]["content"]
            except (KeyError, IndexError) as exc:
                raise FirewallError("Unexpected OpenAI response format") from exc


class AnthropicClient:
    """
    Minimal wrapper for Anthropic Messages API (Claude).

    We assume:
      - API key in ANTHROPIC_API_KEY
      - Model in ANTHROPIC_MODEL (default: claude-3-5-sonnet-latest)
    """

    def __init__(self) -> None:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise FirewallError("ANTHROPIC_API_KEY is not set")

        self._api_key = api_key
        self._model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
        self._base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1")

    async def chat(self, messages: List[Dict[str, str]]) -> str:
        """
        Anthropic uses a slightly different format; we convert the OpenAI-style messages.
        """
        # Convert to Anthropic's "messages" format; we keep it simple: user + assistant turns.
        converted: List[Dict[str, Any]] = []
        for m in messages:
            role = m.get("role", "user")
            content = m.get("content", "")
            if role == "system":
                # We'll prepend system as a separate message of type "system"
                converted.append({"role": "system", "content": content})
            elif role in ("user", "assistant"):
                converted.append({"role": role, "content": content})

        url = f"{self._base_url}/messages"
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        payload = {
            "model": self._model,
            "max_tokens": 1024,
            "messages": converted,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code >= 400:
                raise FirewallError(f"Anthropic API error: {resp.status_code} {resp.text}")

            data = resp.json()
            try:
                # content is a list of blocks; we take the first text block
                blocks = data["content"]
                for block in blocks:
                    if block.get("type") == "text":
                        return block["text"]
                raise FirewallError("Anthropic response has no text block")
            except (KeyError, TypeError) as exc:
                raise FirewallError("Unexpected Anthropic response format") from exc


class GoogleGeminiClient:
    """
    Minimal wrapper for Google Gemini chat API.

    We assume:
      - API key in GEMINI_API_KEY
      - Model in GEMINI_MODEL (default: gemini-1.5-flash)
    """

    def __init__(self) -> None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise FirewallError("GEMINI_API_KEY is not set")

        self._api_key = api_key
        self._model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
        base_url = os.getenv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta")
        self._url = f"{base_url}/models/{self._model}:generateContent"

    async def chat(self, messages: List[Dict[str, str]]) -> str:
        # Concatenate all messages into one user prompt (simple but works for demo)
        # For a real app you’d preserve structure.
        text_parts = []
        for m in messages:
            role = m.get("role", "user")
            content = m.get("content", "")
            text_parts.append(f"{role.upper()}: {content}")
        full_prompt = "\n".join(text_parts)

        params = {"key": self._api_key}
        payload = {
            "contents": [
                {"parts": [{"text": full_prompt}]}
            ]
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(self._url, params=params, json=payload)
            if resp.status_code >= 400:
                raise FirewallError(f"Gemini API error: {resp.status_code} {resp.text}")

            data = resp.json()
            try:
                return data["candidates"][0]["content"]["parts"][0]["text"]
            except (KeyError, IndexError, TypeError) as exc:
                raise FirewallError("Unexpected Gemini response format") from exc


class DeepSeekClient:
    """
    Minimal wrapper for DeepSeek chat completions API.

    We assume:
      - API key in DEEPSEEK_API_KEY
      - Model in DEEPSEEK_MODEL (default: deepseek-chat)
    """

    def __init__(self) -> None:
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            raise FirewallError("DEEPSEEK_API_KEY is not set")

        self._api_key = api_key
        self._model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
        self._base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")

    async def chat(self, messages: List[Dict[str, str]]) -> str:
        url = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
        }
        payload = {
            "model": self._model,
            "messages": messages,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code >= 400:
                raise FirewallError(f"DeepSeek API error: {resp.status_code} {resp.text}")

            data = resp.json()
            try:
                return data["choices"][0]["message"]["content"]
            except (KeyError, IndexError) as exc:
                raise FirewallError("Unexpected DeepSeek response format") from exc


def get_provider_client(name: ProviderName) -> ProviderClient:
    if name == "openai":
        return OpenAIClient()
    if name == "anthropic":
        return AnthropicClient()
    if name == "google":
        return GoogleGeminiClient()
    if name == "deepseek":
        return DeepSeekClient()
    raise FirewallError(f"Unsupported provider: {name}")
