from typing import List, Literal, Dict, Any, Optional

import logging
import os
import re

from pathlib import Path
from collections import Counter

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from firewall.client import LLMFirewallClient
from firewall.config import get_master_key_from_env
from firewall.errors import FirewallError
from firewall.providers import get_provider_client, ProviderName
from firewall.sanitize import sanitize, desanitize
from firewall.errors import CryptoError, DetectionError, SanitizationError

logger = logging.getLogger("pii_firewall_api")

app = FastAPI(title="PII Firewall LLM Proxy", version="0.1.0")
# Serve static files (the UI, CSS, JS) from ./static
app.mount("/static", StaticFiles(directory="static"), name="static")

TOKEN_RE = re.compile(r"⟦([A-Z_]+):([^⟧]+)⟧")

# Default system prompt to ensure proper behavior of the model responses
FIREWALL_SYSTEM_PROMPT = """
You are a language model sitting behind a PII firewall.

The user messages you receive may contain special tokens of the form:

    ⟦TYPE:PAYLOAD⟧

Examples:
    ⟦EMAIL:...⟧, ⟦CARD:...⟧, ⟦NAME:...⟧, ⟦ADDRESS:...⟧, ⟦PHONE:...⟧, ⟦SECRET:...⟧, etc.

These tokens represent encrypted sensitive data. You must follow these rules strictly:

1. Treat every token ⟦TYPE:PAYLOAD⟧ as an opaque ID.
2. NEVER modify, rewrite, truncate, or expand the inside of a token.
   - Do NOT change TYPE.
   - Do NOT change PAYLOAD.
3. You may move or copy the tokens within your reply if it makes sense in context,
   but the text inside the brackets must remain byte-for-byte identical.
4. Do NOT try to infer, guess, or “reconstruct” what the original sensitive data was.
5. Do NOT invent new tokens unless you are explicitly copying one that already appeared in the conversation.

All other text (outside these tokens) should be handled normally: reason, summarize, rewrite, translate, etc., as requested by the user.
""".strip()


# ----------- Request / response models ----------- #

class Message(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str


class DetectedPIISummary(BaseModel):
    type: str
    count: int


class ChatRequest(BaseModel):
    provider: ProviderName = Field(
        default="openai",
        description="Which LLM provider to use (openai, anthropic, google, deepseek).",
    )
    model: Optional[str] = Field(
        default=None,
        description="Optional model override, provider-specific.",
    )
    messages: List[Message]


class ChatResponse(BaseModel):
    sanitized_prompt: str
    raw_llm_reply: str
    final_reply: str
    detected_pii: Optional[List[DetectedPIISummary]] = None


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded", "error"]
    master_key_present: bool
    providers: Dict[str, bool]


class WhoAmIResponse(BaseModel):
    default_provider: Optional[str]
    configured_providers: List[str]
    master_key_present: bool


# ----------- Helpers ----------- #

def _get_master_key() -> bytes:
    return get_master_key_from_env("PII_FIREWALL_KEY")


def _provider_env_status() -> Dict[str, bool]:
    """
    Return a mapping of provider name -> bool indicating whether
    the corresponding API key env var is set.
    """
    return {
        "openai": bool(os.getenv("OPENAI_API_KEY")),
        "anthropic": bool(os.getenv("ANTHROPIC_API_KEY")),
        "google": bool(os.getenv("GEMINI_API_KEY")),
        "deepseek": bool(os.getenv("DEEPSEEK_API_KEY")),
    }


def _build_firewalled_client(provider: ProviderName) -> LLMFirewallClient:
    """
    Build an LLMFirewallClient wrapping the selected provider.

    (Currently unused in this API. We handle sanitize/desanitize manually
    in the /v1/chat/completions endpoint.)
    """
    raise NotImplementedError("This helper is not used directly in the API yet")


# ----------- Routes ----------- #

@app.post("/v1/chat/completions", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """
    Entry point: behaves like a mini OpenAI-compatible chat endpoint,
    but with an extra 'provider' field and PII firewall in front.
    """
    try:
        master_key = _get_master_key()
    except FirewallError as exc:
        logger.error("Config error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    # Build provider client
    try:
        provider_client = get_provider_client(request.provider)
    except FirewallError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Simple strategy:
    #  - Join all user+system messages into one string to send to the firewall.
    #  - For demo purposes, we treat the whole conversation as a single prompt.
    lines: List[str] = []
    for m in request.messages:
        lines.append(f"{m.role.upper()}: {m.content}")
    user_text = "\n".join(lines)

    # LLM call wrapper: always add firewall system prompt,
    # then user system messages, then the sanitized conversation.
    async def async_llm_call(prompt: str) -> str:
        """
        Wrap the sanitized prompt into messages for the provider.

        - Always prepend the firewall system prompt.
        - Then include any user-provided system messages.
        - Then send the combined, sanitized conversation as a single user message.
        """
        provider_messages: List[Dict[str, Any]] = []

        # 1) Our firewall system prompt (always present)
        provider_messages.append(
            {"role": "system", "content": FIREWALL_SYSTEM_PROMPT}
        )

        # 2) User-provided system messages (optional)
        for m in request.messages:
            if m.role == "system":
                provider_messages.append(
                    {"role": "system", "content": m.content}
                )

        # 3) The sanitized conversation as a single user message
        provider_messages.append(
            {"role": "user", "content": prompt}
        )

        return await provider_client.chat(provider_messages)

    # 1) Outgoing firewall
    try:
        sanitized_prompt = sanitize(user_text, master_key)
    except FirewallError as exc:
        logger.error("Sanitization error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    matches = TOKEN_RE.findall(sanitized_prompt)
    detected_pii: Optional[List[DetectedPIISummary]] = None
    if matches:
        counts = Counter(t for (t, _) in matches)
        detected_pii = [
            DetectedPIISummary(type=t, count=counts[t])
            for t in sorted(counts.keys())
        ]

    # 2) LLM call (async)
    try:
        raw_reply = await async_llm_call(sanitized_prompt)
    except FirewallError as exc:
        logger.error("LLM provider error: %s", exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Unexpected error when calling provider")
        raise HTTPException(status_code=502, detail="Unexpected error from LLM provider") from exc

    # 3) Incoming firewall
    try:
        final_reply = desanitize(raw_reply, master_key, mode="original")
    except FirewallError as exc:
        logger.error("Desanitization error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return ChatResponse(
        sanitized_prompt=sanitized_prompt,
        raw_llm_reply=raw_reply,
        final_reply=final_reply,
        detected_pii=detected_pii,
    )


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """
    Lightweight health check:

      - status: 'ok' if master key present AND at least one provider configured
                'degraded' if only one of those is true
                'error' if neither is true
      - master_key_present: whether PII_FIREWALL_KEY is set and valid
      - providers: which provider API keys are present (True/False)
    """
    providers = _provider_env_status()

    try:
        _ = _get_master_key()
        master_key_present = True
    except FirewallError:
        master_key_present = False

    any_provider = any(providers.values())

    if master_key_present and any_provider:
        status: Literal["ok", "degraded", "error"] = "ok"
    elif master_key_present or any_provider:
        status = "degraded"
    else:
        status = "error"

    return HealthResponse(
        status=status,
        master_key_present=master_key_present,
        providers=providers,
    )


@app.get("/whoami", response_model=WhoAmIResponse)
async def whoami() -> WhoAmIResponse:
    """
    Introspection endpoint that tells you:

      - which providers have API keys configured
      - which provider is considered the default
      - whether the master key is present

    No secrets are returned, only names/booleans.
    """
    providers = _provider_env_status()

    try:
        _ = _get_master_key()
        master_key_present = True
    except FirewallError:
        master_key_present = False

    configured = [name for name, ok in providers.items() if ok]

    # Default provider heuristic:
    # 1. explicit env var PII_FIREWALL_DEFAULT_PROVIDER
    # 2. 'openai' if configured
    # 3. first configured provider
    default = os.getenv("PII_FIREWALL_DEFAULT_PROVIDER")
    if not default:
        if "openai" in configured:
            default = "openai"
        elif configured:
            default = configured[0]
        else:
            default = None

    return WhoAmIResponse(
        default_provider=default,
        configured_providers=configured,
        master_key_present=master_key_present,
    )


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    """
    Serve the main UI page.
    """
    index_path = Path("static") / "index.html"
    try:
        return index_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return "<h1>PII Firewall UI</h1><p>static/index.html not found.</p>"

