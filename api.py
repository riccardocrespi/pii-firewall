from typing import List, Literal, Dict, Any, Optional

import logging
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from firewall.client import LLMFirewallClient
from firewall.config import get_master_key_from_env
from firewall.errors import FirewallError
from firewall.providers import get_provider_client, ProviderName

logger = logging.getLogger("pii_firewall_api")

app = FastAPI(title="PII Firewall LLM Proxy", version="0.1.0")


# ----------- Request / response models ----------- #

class Message(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str


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
    """
    master_key = _get_master_key()
    provider_client = get_provider_client(provider)

    async def llm_call(prompt: str) -> str:
        # We adapt from simple string prompt to a messages list with one user message.
        messages = [{"role": "user", "content": prompt}]
        return await provider_client.chat(messages)

    # LLMFirewallClient expects a sync callable, but our provider is async.
    # We'll wrap it via anyio/asyncio in the endpoint instead, so here we just
    # pass a dummy; the actual call happens in the endpoint.
    # To keep the client reusable, we define a sync proxy in the endpoint.
    raise NotImplementedError("This helper is not used directly")


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
    lines = []
    for m in request.messages:
        lines.append(f"{m.role.upper()}: {m.content}")
    user_text = "\n".join(lines)

    # We need a sync llm_call that the firewall client can use.
    # Internally, it will await the async provider.
    async def async_llm_call(prompt: str) -> str:
        # Wrap sanitized prompt into messages for the provider.
        provider_messages: List[Dict[str, Any]] = [
            {"role": "user", "content": prompt}
        ]
        return await provider_client.chat(provider_messages)

    # Small async wrapper around LLMFirewallClient
    # We'll instantiate it with the master key and a sync shim.
    # To avoid mixing sync/async too much, we call sanitize/desanitize ourselves.

    from firewall.sanitize import sanitize, desanitize

    # 1) Outgoing firewall
    from firewall.errors import CryptoError, DetectionError, SanitizationError  # optional

    try:
        sanitized_prompt = sanitize(user_text, master_key)
    except FirewallError as exc:
        logger.error("Sanitization error: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

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

