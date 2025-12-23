# Architecture Overview

This document describes the main components of the PII Firewall and how they interact.

---

## High-level data flow

For a typical request:

1. User sends a prompt to the **local proxy** (FastAPI app).
2. The proxy:
   - concatenates messages into a prompt string,
   - runs `sanitize(prompt, master_key)` → produces a **sanitized prompt**.
3. The sanitized prompt is sent to the **LLM provider** (OpenAI / Anthropic / Gemini / DeepSeek).
4. The provider returns a reply that may contain tokens like `⟦EMAIL:...⟧`.
5. The proxy runs `desanitize(reply, master_key)` to restore plaintext locally.
6. The caller receives a final reply (with or without PII, depending on mode).

---

## Layered view

```text
[ User / Client ]
       │
       ▼
[ FastAPI Proxy: api.py ]
  - /v1/chat/completions
  - /health
  - /whoami
       │
       ├─ sanitize(user_text, key)
       │     │
       │     ▼
       │  [ Detection Layer ]
       │   - firewall/detection_regex.py
       │
       ├─ [ Provider Layer ]
       │   - firewall/providers.py
       │   - HTTP calls (OpenAI, Anthropic, Gemini, DeepSeek)
       │
       └─ desanitize(raw_llm_reply, key)
             │
             ▼
      [ Final reply to user ]
```

The library itself can also be used directly without the proxy via `LLMFirewallClient`.

---

## Modules

### 1. Detection (`firewall/detection_regex.py`)

Responsibilities:

- Find PII spans based on regular expressions:
  - `EMAIL`, `PHONE`, `CARD`, `ID`, `SECRET`, `ADDRESS`, `OTHER_PII`
- Return a list of `Span(type, start, end)` objects.
- Merge overlapping spans conservatively.
- Wrap any unexpected failures in `DetectionError` and log them.

Future extension:

- A ML/BERT-based detector can be added in a separate module and plugged into `sanitize()` via a detector interface.

---

### 2. Crypto (`firewall/crypto_aes_gcm.py`)

Responsibilities:

- Encrypt and decrypt PII values using AES-GCM with:
  - per-type subkeys derived from a master key using HKDF,
  - padded plaintexts to reduce length leakage,
  - associated data (AAD) bound to the PII type (prevents type swapping attacks).
- `encrypt_pii(value, pii_type, master_key) -> str` returns a base64url string.
- `decrypt_pii(token, pii_type, master_key) -> str` recovers the original value.

Errors:

- Use `CryptoError` when:
  - master key is invalid,
  - ciphertext is malformed,
  - authentication fails,
  - decoded data is inconsistent.

Other crypto modules:

- `crypto_simple.py` and/or `crypto_dummy.py` may contain legacy or test-only schemes; they are **not** intended for production use.

---

### 3. Core pipeline (`firewall/sanitize.py`)

Responsibilities:

- `sanitize(text, key, detector=detect_spans)`:
  - runs the detector,
  - for each PII span:
    - extracts the substring,
    - calls `encrypt_pii`,
    - replaces it with a token: `⟦TYPE:BASE64⟧`.
  - returns the sanitized text.

- `desanitize(text, key, mode="original")`:
  - finds tokens of the form `⟦TYPE:PAYLOAD⟧`,
  - if `mode="encrypted"`: leaves tokens as-is,
  - if `mode="original"`: decrypts `PAYLOAD` for each `TYPE` and replaces the token with plaintext.

Token format:

```text
⟦TYPE:PAYLOAD⟧

TYPE    = uppercase label (e.g., EMAIL, CARD, SECRET, ...)
PAYLOAD = AES-GCM ciphertext encoded as base64url
```

Examples:

```text
"My email is ⟦EMAIL:AbCdEf...⟧ and my card is ⟦CARD:XyZ...⟧."
```

The LLM provider sees opaque tokens with no direct hint of the plaintext.

On the way back, `desanitize()`:

- finds `⟦TYPE:PAYLOAD⟧` tokens,
- calls `decrypt_pii(PAYLOAD, TYPE, master_key)`,
- replaces tokens with plaintext (in `mode="original"`),
- leaves tokens intact if `mode="encrypted"`.

---

### 4. Config (`firewall/config.py`)

Responsibilities:

- Load the **master key** for AES-GCM from environment.
- Validate its length (≥ 32 bytes).
- Raise `ConfigError` (a subclass of `FirewallError`) if not set or invalid.

Typical usage:

```python
from firewall.config import get_master_key_from_env

key = get_master_key_from_env("PII_FIREWALL_KEY")
```

---

### 5. Error hierarchy (`firewall/errors.py`)

- `FirewallError` – base class for all project-specific errors.
- `CryptoError` – crypto failures.
- `DetectionError` – detection-related failures.
- `SanitizationError` – sanitize/desanitize pipeline issues.
- `ConfigError` – configuration problems (missing/invalid keys).

This allows the app layer to:

- catch specific errors where needed,
- or catch `FirewallError` as a generic “firewall failed” exception.

---

### 6. LLM client wrapper (`firewall/client.py`)

`LLMFirewallClient` is a high-level wrapper that can sit around any LLM-like callable:

- Constructor:

  ```python
  client = LLMFirewallClient(master_key, llm_call)
  # or
  client = LLMFirewallClient.from_env(llm_call)
  ```

- `ask(user_text, mode="original")`:

  - sanitize `user_text`,
  - send sanitized text to `llm_call`,
  - desanitize the reply,
  - returns a triple: `(sanitized_prompt, raw_llm_reply, final_reply)`.

This abstraction is used in the CLI demo and can be reused in other applications.

---

### 7. Provider abstraction (`firewall/providers.py`)

Implements per-provider HTTP clients with a unified interface:

- `ProviderClient.chat(messages: List[{"role": ..., "content": ...}]) -> str`
- Supported providers:
  - `OpenAIClient`
  - `AnthropicClient`
  - `GoogleGeminiClient`
  - `DeepSeekClient`
- `get_provider_client(name)` returns the appropriate client instance.

Each client:

- reads its API key and model name from environment,
- maps a simple messages format to the provider’s actual API,
- raises `FirewallError` on HTTP/API errors.

---

### 8. FastAPI proxy (`api.py`)

Main entrypoint for the “full app”:

- `POST /v1/chat/completions`:
  - request: `{ provider, model?, messages }`
  - pipeline:
    1. load master key,
    2. build provider client,
    3. flatten `messages` into a prompt string for firewall,
    4. `sanitize` → `async` provider call → `desanitize`,
    5. return `{ sanitized_prompt, raw_llm_reply, final_reply }`.

- `GET /health`:
  - reports status (`ok` / `degraded` / `error`),
  - whether master key is present,
  - which providers have API keys.

- `GET /whoami`:
  - lists configured providers,
  - inferred default provider,
  - master key presence.

---

### 9. CLI (`cli.py`)

Thin wrapper around `LLMFirewallClient` for local demos:

- Reads master key from env.
- Uses a simple fake LLM function that echoes the sanitized prompt.
- Outputs:
  - original input,
  - sanitized prompt,
  - raw LLM reply,
  - final reply.

---

## Extensibility

- **ML-based detection**:
  - Add a new module (e.g. `detection_ml.py`),
  - implement a function compatible with the detector interface,
  - plug it into `sanitize()` (optional parameter or config flag).

- **Additional providers**:
  - Create new client classes in `providers.py`,
  - add them to `ProviderName` and `get_provider_client()`.

- **Policy engine**:
  - Introduce a config layer specifying which PII types to mask,
  - or different modes per type (e.g., never decrypt `SECRET` fields).

This architecture is designed so that these extensions require minimal changes to existing code.
