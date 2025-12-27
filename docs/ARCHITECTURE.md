# Architecture

This document describes the overall architecture of the PII Firewall, how data flows through the system, and how the main modules fit together.

## High-level picture

The project is built as a **library** plus a **web proxy** and a **CLI demo**.

```text
[ User (browser or CLI) ]
          │
          ▼
[ Application / Proxy ]
  - api.py (FastAPI)
  - cli.py
          │
          ├─ sanitize(user_text, master_key)
          │     ├─ detection_combined.detect_spans_combined()
          │     │      ├─ detection_regex.detect_spans()
          │     │      └─ ml_detector.MLDetector.detect_spans()
          │     └─ crypto_aes_gcm.encrypt_pii()
          │
          ├─ Provider client (providers.py)
          │     ├─ OpenAIClient
          │     ├─ AnthropicClient
          │     ├─ GoogleGeminiClient
          │     └─ DeepSeekClient
          │
          └─ desanitize(raw_reply, master_key)
                └─ crypto_aes_gcm.decrypt_pii()
```

The **sanitization pipeline** is independent of any specific LLM provider: it only sees text. Provider-specific details are isolated inside `providers.py`.

## Core concepts

### Spans

`firewall/spans.py` defines a `Span` dataclass:

```python
@dataclass
class Span:
    type: str   # e.g. "EMAIL", "CARD", "NAME"
    start: int  # inclusive character offset
    end: int    # exclusive character offset
```

The detector outputs a list of spans; `sanitize()` uses them to slice and encrypt.

### Errors

`firewall/errors.py` defines:

- `FirewallError` – base class for all project-specific errors.
- `CryptoError` – crypto layer failures.
- `DetectionError` – detection layer failures (regex or ML).
- `SanitizationError` – failures in `sanitize()` / `desanitize()`.

Higher-level code (CLI, API) catches `FirewallError` and surfaces a friendly message.

## Detection layer

### Regex detection (`detection_regex.py`)

Responsibilities:

- Use regular expressions to detect structured PII types:
  - `EMAIL`, `PHONE`, `CARD`, `ID`, `SECRET`, `ADDRESS`, `OTHER_PII`.
- Construct `Span` objects for each match.
- Merge overlapping spans conservatively:
  - `CARD` wins over `PHONE` when ranges overlap,
  - `ID` can override `PHONE` if they overlap,
  - overlapping spans of the same type are merged.

Detection errors are wrapped as `DetectionError`.

### ML detection (`ml_detector.py`)

Responsibilities:

- Load a HuggingFace NER pipeline (`dslim/bert-base-NER`) once per process.
- Normalize casing with `normalize_for_ner()`:
  - Title-case per word,
  - only ASCII letters modified,
  - string length preserved (indices stay valid).
- Run NER and map entity groups to PII types:
  - `PER` → `NAME`
  - `LOC` → `ADDRESS`
  - `ORG` → `OTHER_PII`
- Filter low-confidence entities and merge overlapping spans of the same type.

This layer is better at names and many addresses than regex alone.

### Combined detection (`detection_combined.py`)

`detect_spans_combined(text: str) -> List[Span]`:

1. Run regex detection.
2. Run ML detection.
3. Concatenate, sort by `(start, end)`.
4. Merge overlaps with precedence:
   - “strong” types (`EMAIL`, `CARD`, `SECRET`, `PHONE`, `ID`) override weaker ML spans,
   - equal-strength spans merge by extending their end offset.

`sanitize()` calls `_detect_spans_with_fallback()`:

- try combined detection first,
- on failure (e.g. missing model, CUDA issues) log a warning and fall back to regex-only,
- on total failure, raise `DetectionError`.

## Crypto layer

Implemented in `firewall/crypto_aes_gcm.py` (see `docs/CRYPTO.md` for details).

Highlights:

- AES‑256‑GCM with per-type HKDF subkeys,
- bucketed padding with a 2-byte length prefix,
- AAD bound to `pii_type` to prevent type swapping,
- `encrypt_pii()` / `decrypt_pii()` are the only public entry points.

## Sanitization pipeline (`sanitize.py`)

`sanitize(text: str, key: bytes) -> str`:

1. Detect spans via `_detect_spans_with_fallback(text)`.
2. Sort by `start`.
3. Iterate over the text, emitting non-PII segments unchanged.
4. For each span:
   - slice the substring,
   - encrypt it with `encrypt_pii()`,
   - replace it with a token `⟦TYPE:PAYLOAD⟧`.
5. Return the concatenated result.

On detection or crypto errors, raise `SanitizationError`.

### Desanitization

`desanitize(text: str, key: bytes, mode: str = "original") -> str`:

- Finds tokens via regex (`⟦([A-Z_]+):([^⟧]+)⟧`).

Modes:

- `"original"` – decrypt each token with `decrypt_pii()` and replace it by plaintext.
- `"encrypted"` – leave tokens as-is.

If decryption fails, raise `SanitizationError`.

## High-level client (`client.py`)

`LLMFirewallClient` wraps an arbitrary LLM callable (real or fake):

```python
client = LLMFirewallClient.from_env(llm_call)
sanitized, raw_reply, final_reply = client.ask("Some text with PII")
```

- `sanitize_outgoing()` – apply `sanitize()`,
- `desanitize_incoming()` – apply `desanitize()`,
- `ask()` – full roundtrip through sanitize → LLM → desanitize,
- wraps unknown errors as `FirewallError("Unexpected error in LLMFirewallClient.ask()")`.

## Provider layer (`providers.py`)

Defines:

- `ProviderName`: `"openai" | "anthropic" | "google" | "deepseek"`.
- `ProviderClient` protocol: `async def chat(self, messages: List[Dict[str, str]]) -> str`.
- Concrete implementations:
  - `OpenAIClient` – `/chat/completions`.
  - `AnthropicClient` – Messages API (`/v1/messages`). 
  - `GoogleGeminiClient` – `generateContent`.
  - `DeepSeekClient` – OpenAI-compatible chat completions.

Each client:

- reads API key, base URL and model name from env,
- converts OpenAI-style `messages` into provider-specific request bodies,
- calls `_raise_for_insufficient_or_generic()` on HTTP errors:
  - maps “insufficient balance / credit” messages to `FirewallError("INSUFFICIENT_BALANCE")`,
  - otherwise wraps provider JSON into a generic `FirewallError`.

`get_provider_client(name: ProviderName)` returns the appropriate client or raises on unsupported providers.

## FastAPI proxy (`api.py`)

Main endpoints:

- `GET /health` – status, master key presence, configured providers.
- `GET /whoami` – which providers are configured + default provider.
- `POST /v1/chat/completions` – OpenAI-style chat route with extra `provider` field.

Chat flow:

1. Load master key.
2. Instantiate provider client from `provider` field or fallback default.
3. Flatten incoming `messages` into a single conversation text.
4. Call `sanitize(text, master_key)`.
5. Build provider `messages` including:
   - a system prompt describing token semantics,
   - optional user-supplied system content,
   - one `user` message with the sanitized conversation.
6. Call `await client.chat(messages)`.
7. Call `desanitize(raw_reply, master_key)`.
8. Collect token types from `sanitized_prompt` to build `detected_pii` summary.
9. Return the JSON response consumed by the UI.

Error mapping:

- `INSUFFICIENT_BALANCE` → HTTP 402 with small JSON payload.
- Provider errors → HTTP 502 with detail.
- Firewall errors (crypto/detection/sanitization) → HTTP 500.

## Web UI (`static/index.html`)

Single-page app (Tailwind + vanilla JS) that:

- Calls `/health` + `/whoami` on load to show status and configured providers.
- Maintains a message history in memory and posts it to `/v1/chat/completions`.
- Renders:
  - detected PII types and counts,
  - sanitized prompt,
  - raw LLM reply,
  - final reply.
- Supports:
  - provider selection + optional model override,
  - system prompt text area,
  - light/dark mode toggle,
  - reset chat button,
  - modal popup if the backend returns `INSUFFICIENT_BALANCE`.

## CLI (`cli.py`)

A small command-line interface that wraps a demo LLM in `LLMFirewallClient` to show:

- how text is sanitized,
- what a “raw” reply looks like with tokens,
- how final output is reconstructed for local display.

Useful for experiments without running the HTTP server or web UI.

## Future work

- Richer policy engine (per-type rules, “never decrypt SECRET”).
- Streaming chat responses (SSE or websockets).
- Additional PII categories and detectors.
- Stronger key management and rotation strategies.

