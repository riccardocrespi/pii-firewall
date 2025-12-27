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


def _raise_for_insufficient_or_generic(provider: str, resp: httpx.Response) -> None:
    """
    Helper to normalize provider HTTP errors.

    - If the JSON body contains an error message that clearly indicates lack of
      credits / balance, raise FirewallError("INSUFFICIENT_BALANCE").
    - Otherwise, raise FirewallError with a generic provider error message.
    """
    try:
        data = resp.json()
    except Exception:
        raise FirewallError(
            f"{provider} API error: {resp.status_code} {resp.text}"
        )

    err = data.get("error") or {}
    msg = (err.get("message") or "").strip()
    code = (err.get("code") or "").strip().lower()
    lower = msg.lower()

    # Heuristics for "no money" / "no credits":
    #  - Generic "Insufficient Balance" style messages
    #  - Anthropic-style "Your credit balance is too low to access the ..."
    if (
        "insufficient" in lower
        or ("balance" in lower and "low" in lower)
        or "credit balance" in lower
        or code in {"insufficient_balance", "insufficient_quota"}
    ):
        raise FirewallError("INSUFFICIENT_BALANCE")

    # Fallback: generic error with full JSON
    raise FirewallError(f"{provider} API error: {resp.status_code} {data}")



# -------------------- OpenAI -------------------- #


class OpenAIClient:
    """
    Minimal wrapper for OpenAI Chat Completions API (gpt-4.x / gpt-3.5-like).

    We assume:
      - API key in OPENAI_API_KEY
      - Model name in OPENAI_MODEL (default: gpt-4o-mini)
      - Base URL in OPENAI_BASE_URL (default: https://api.openai.com/v1)
    """

    def __init__(self) -> None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise FirewallError("OPENAI_API_KEY is not set")

        self._api_key = api_key
        self._model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        self._base_url = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

    async def chat(self, messages: List[Dict[str, str]]) -> str:
        """
        POST {base_url}/chat/completions

        Headers:
          Authorization: Bearer <OPENAI_API_KEY>
          Content-Type: application/json

        Body:
          {
            "model": "<OPENAI_MODEL>",
            "messages": [ { "role": "...", "content": "..." }, ... ]
          }
        """
        url = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self._model,
            "messages": messages,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code >= 400:
                _raise_for_insufficient_or_generic("OpenAI", resp)

            data = resp.json()
            try:
                return data["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError) as exc:
                raise FirewallError("Unexpected OpenAI response format") from exc


# -------------------- Anthropic (Claude) -------------------- #


class AnthropicClient:
    """
    Minimal wrapper for Anthropic Claude Messages API.

    We assume:
      - API key in ANTHROPIC_API_KEY
      - Model in ANTHROPIC_MODEL (default: claude-3-5-sonnet-latest)
      - Base URL in ANTHROPIC_BASE_URL (default: https://api.anthropic.com/v1)
      - API version in ANTHROPIC_API_VERSION (default: 2023-06-01)
    """

    def __init__(self) -> None:
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise FirewallError("ANTHROPIC_API_KEY is not set")

        self._api_key = api_key
        self._model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
        self._base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1")
        self._version = os.getenv("ANTHROPIC_API_VERSION", "2023-06-01")

    def _build_payload(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Convert OpenAI-style messages into Anthropic's Messages API format.

        - Collect all role == "system" messages into a single top-level `system` string.
        - Keep `user` and `assistant` messages as-is in the `messages` array.

        Anthropic's examples use `role` ∈ {"user","assistant"} for messages, with
        an optional separate `system` field.
        """
        convo: List[Dict[str, Any]] = []
        system_texts: List[str] = []

        for m in messages:
            role = m.get("role", "user")
            content = m.get("content", "")
            if not content:
                continue

            if role == "system":
                system_texts.append(content)
                continue

            if role not in ("user", "assistant"):
                role = "user"

            # For pure text you can use the shorthand 'content: str'
            convo.append({"role": role, "content": content})

        if not convo:
            raise FirewallError("Anthropic: no user/assistant messages to send")

        payload: Dict[str, Any] = {
            "model": self._model,
            "max_tokens": 1024,
            "messages": convo,
        }

        if system_texts:
            payload["system"] = "\n\n".join(system_texts)

        return payload

    async def chat(self, messages: List[Dict[str, str]]) -> str:
        """
        Send a multi-turn chat request to Claude via the Messages API.

        Endpoint:
          POST {base_url}/messages  (default: https://api.anthropic.com/v1/messages)
        """
        url = f"{self._base_url}/messages"
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": self._version,
            "content-type": "application/json",
        }
        payload = self._build_payload(messages)

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code >= 400:
                _raise_for_insufficient_or_generic("Anthropic", resp)

            data = resp.json()
            try:
                # Claude Messages API returns `content` as a list of blocks:
                #   { "content": [ { "type": "text", "text": "..." }, ... ], ... }
                blocks = data["content"]
                for block in blocks:
                    if block.get("type") == "text":
                        return block["text"]
                raise FirewallError("Anthropic response has no text block")
            except (KeyError, TypeError) as exc:
                raise FirewallError("Unexpected Anthropic response format") from exc


# -------------------- Google Gemini -------------------- #


class GoogleGeminiClient:
    """
    Minimal wrapper for Google Gemini chat API (generateContent).

    We assume:
      - API key in GEMINI_API_KEY
      - Model in GEMINI_MODEL (default: gemini-2.5-flash)
      - Base URL in GEMINI_BASE_URL (default: https://generativelanguage.googleapis.com/v1beta)

    Mapping from our messages -> Gemini request:

      - role == "system"    -> system_instruction.parts[].text
      - role == "user"      -> contents[].role = "user"
      - role == "assistant" -> contents[].role = "model"
    """

    def __init__(self) -> None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise FirewallError("GEMINI_API_KEY is not set")

        self._api_key = api_key
        self._model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
        base_url = os.getenv(
            "GEMINI_BASE_URL",
            "https://generativelanguage.googleapis.com/v1beta",
        )
        self._url = f"{base_url}/models/{self._model}:generateContent"

    def _build_payload(self, messages: List[Dict[str, str]]) -> Dict[str, Any]:
        contents: List[Dict[str, Any]] = []
        system_texts: List[str] = []

        for msg in messages:
            role = msg.get("role", "user")
            text = msg.get("content", "")

            if not text:
                continue

            if role == "system":
                system_texts.append(text)
                continue

            if role == "assistant":
                gemini_role = "model"
            else:
                gemini_role = "user"

            contents.append(
                {
                    "role": gemini_role,
                    "parts": [{"text": text}],
                }
            )

        if not contents:
            raise FirewallError("Gemini: no non-system messages to send")

        payload: Dict[str, Any] = {"contents": contents}

        if system_texts:
            payload["system_instruction"] = {
                "parts": [{"text": "\n\n".join(system_texts)}]
            }

        return payload

    async def chat(self, messages: List[Dict[str, str]]) -> str:
        """
        Send a multi-turn chat request to Gemini using generateContent.
        """
        headers = {
            "x-goog-api-key": self._api_key,
            "Content-Type": "application/json",
        }
        payload = self._build_payload(messages)

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(self._url, headers=headers, json=payload)
            if resp.status_code >= 400:
                _raise_for_insufficient_or_generic("Gemini", resp)

            data = resp.json()
            try:
                # candidates[0].content.parts[*].text
                candidates = data["candidates"]
                if not candidates:
                    raise KeyError("no candidates")
                first = candidates[0]
                parts = first["content"]["parts"]
                texts = [p.get("text", "") for p in parts if isinstance(p, dict)]
                return "".join(texts).strip()
            except (KeyError, IndexError, TypeError) as exc:
                raise FirewallError("Unexpected Gemini response format") from exc


# -------------------- DeepSeek -------------------- #


class DeepSeekClient:
    """
    Minimal wrapper for DeepSeek chat completions API.

    We assume:
      - API key in DEEPSEEK_API_KEY
      - Model in DEEPSEEK_MODEL (default: deepseek-chat)
      - Base URL in DEEPSEEK_BASE_URL (default: https://api.deepseek.com/v1)
    """

    def __init__(self) -> None:
        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key:
            raise FirewallError("DEEPSEEK_API_KEY is not set")

        self._api_key = api_key
        self._model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
        self._base_url = os.getenv(
            "DEEPSEEK_BASE_URL",
            "https://api.deepseek.com/v1",
        )

    async def chat(self, messages: List[Dict[str, str]]) -> str:
        """
        OpenAI-compatible DeepSeek Chat API.

        POST {base_url}/chat/completions
        Headers:
          Authorization: Bearer <api_key>
          Content-Type: application/json

        Body:
          {
            "model": "deepseek-chat",
            "messages": [ { "role": "...", "content": "..." }, ... ]
          }
        """
        url = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self._model,
            "messages": messages,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code >= 400:
                _raise_for_insufficient_or_generic("DeepSeek", resp)

            data = resp.json()
            try:
                return data["choices"][0]["message"]["content"]
            except (KeyError, IndexError, TypeError) as exc:
                raise FirewallError("Unexpected DeepSeek response format") from exc


# -------------------- Factory -------------------- #


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