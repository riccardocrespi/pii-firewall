# Usage guide

This guide shows how to **run and use** the PII Firewall in practice:

- as a **CLI tool**,
- as a **FastAPI proxy + web UI**,
- as a **Python library** in your own code.

It assumes you already:

- cloned the repo,
- created a virtualenv,
- installed dependencies with `pip install -r requirements.txt`,
- created and filled a `.env` from `env.example` and loaded it:

```bash
cp env.example .env
set -a; source .env; set +a
```

---

## 1. CLI usage

The CLI (`cli.py`) lets you try the firewall locally without running the HTTP server or using real LLM APIs.

### 1.1 Basic example

```bash
python cli.py "My email is john.doe@example.com and my card is 4111 1111 1111 1111."
```

Output (conceptually):

1. **Sanitized prompt** – the text that would be sent to the LLM:
   ```text
   My email is ⟦EMAIL:...⟧ and my card is ⟦CARD:...⟧.
   ```
2. **Raw LLM reply** – fake LLM output that still contains tokens.
3. **Final reply** – after `desanitize()`, where tokens are decrypted and replaced locally.

### 1.2 Encrypted-only mode

If you want to see what it looks like **without restoring PII**, use:

```bash
python cli.py --mode encrypted "My phone is +1 415 555 1234."
```

In this mode:

- the outgoing prompt is still sanitized,
- the reply is **not** desanitized: tokens remain as `⟦TYPE:...⟧`.

### 1.3 Verbose mode

To see more internal details (e.g. spans, token boundaries), run:

```bash
python cli.py -v "Here is an AWS key AKIAIOSFODNN7EXAMPLE."
```

This is useful when debugging regex/ML detection or crypto.


---

## 2. FastAPI proxy + Web UI

The FastAPI app (`api.py`) exposes:

- a **REST API** for programmatic use,
- a **single-page web UI** under `/`.

### 2.1 Start the server

From the repo root:

```bash
uvicorn api:app --reload
# or (explicit dotenv)
uvicorn api:app --reload --env-file .env
```

The server runs on `http://127.0.0.1:8000` by default.

### 2.2 Web UI

Open:

- `http://127.0.0.1:8000/`

You can:

- choose a **provider** (OpenAI / Anthropic / Gemini / DeepSeek),
- optionally set a **model name** (or leave it empty to use the default from env),
- specify an optional **system prompt**,
- type a **user message** and send it,
- carry on a **multi-turn conversation** (history is tracked in the browser),
- see:
  - which PII types were detected (and how many occurrences),
  - the **sanitized prompt**,
  - the **raw LLM reply**,
  - the **final reply** with PII restored locally,
- toggle **light/dark mode**,
- **reset** the conversation.

If the provider returns an “insufficient balance / credit” style error:

- the backend normalizes it,
- the UI shows a **modal popup** explaining the issue,
- an inline error appears under the form.

### 2.3 Health & introspection endpoints

Useful for debugging configuration:

- `GET /health`  
  Returns a JSON dict with:
  - `status`: `"ok" | "degraded" | "error"`,
  - `master_key_present`: bool,
  - `providers`: which providers have keys set.

- `GET /whoami`  
  Returns:
  - `configured_providers` – list of providers with API keys configured,
  - `default_provider` – the provider used when none is specified,
  - `master_key_present` – whether crypto is configured.

Try from terminal:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/whoami
```


---

## 3. Calling the API programmatically

The main entrypoint is `POST /v1/chat/completions`. It is intentionally similar to the OpenAI Chat Completions API, but with an extra `provider` field.

### 3.1 Simple request (curl)

```bash
curl -X POST http://127.0.0.1:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "openai",
    "model": null,
    "messages": [
      {
        "role": "user",
        "content": "My email is john.doe@example.com and my card is 4111 1111 1111 1111. Please summarize."
      }
    ]
  }'
```

Response (simplified shape):

```json
{
  "sanitized_prompt": "USER: My email is ⟦EMAIL:...⟧ and my card is ⟦CARD:...⟧. Please summarize.",
  "raw_llm_reply": "Here is a summary: ... ⟦EMAIL:...⟧ ... ⟦CARD:...⟧ ...",
  "final_reply": "Here is a summary: ... john.doe@example.com ... 4111 1111 1111 1111 ...",
  "detected_pii": [
    {"type": "EMAIL", "count": 1},
    {"type": "CARD", "count": 1}
  ]
}
```

Notes:

- `provider` can be `"openai"`, `"anthropic"`, `"google"`, or `"deepseek"`.
- If `model` is `null`, the provider’s default model from your `.env` is used.
- `messages` may hold the **full conversation history** (system, user, assistant).

### 3.2 Handling errors

If a provider has **no credits / insufficient balance**, the API returns HTTP `402`:

```json
{
  "error_type": "INSUFFICIENT_BALANCE",
  "provider": "anthropic",
  "message": "Your account has insufficient balance with this provider."
}
```

Your client code can branch on `status == 402` and `error_type == "INSUFFICIENT_BALANCE"` to show a friendly message.

Other failures:

- **Provider errors** → HTTP `502` with `{"detail": "..."}`.
- **Internal firewall errors** (crypto/detection/sanitization) → HTTP `500` with `{"detail": "..."}`.


---

## 4. Using the library directly

You can embed the firewall into your own Python code without going through HTTP.

### 4.1 Basic sanitize / desanitize

```python
from firewall.config import get_master_key_from_env
from firewall.sanitize import sanitize, desanitize

master_key = get_master_key_from_env()

user_text = "My email is john.doe@example.com."
sanitized = sanitize(user_text, master_key)
print("Sanitized:", sanitized)

# Pretend we got some LLM reply containing tokens
fake_reply = f"Sure, I will contact you at {sanitized.split()[-1]}."
final = desanitize(fake_reply, master_key, mode="original")
print("Final:", final)
```

### 4.2 Wrapping a custom LLM with LLMFirewallClient

`LLMFirewallClient` sits around an arbitrary callable that behaves like an LLM.

Example with a dummy LLM:

```python
from firewall.client import LLMFirewallClient
from firewall.config import get_master_key_from_env

def fake_llm(prompt: str) -> str:
    # A trivial, illustrative LLM-like function
    return f"[FAKE LLM REPLY] {prompt}"

master_key = get_master_key_from_env()
client = LLMFirewallClient(fake_llm, master_key=master_key)

sanitized, raw_reply, final_reply = client.ask(
    "My phone is +1 415 555 1234 and my email is john.doe@example.com."
)

print("Sanitized prompt:", sanitized)
print("Raw LLM reply:", raw_reply)
print("Final reply:", final_reply)
```

You can adapt this pattern around any real LLM client that accepts a string and returns a string.

---

## 5. Configuration recap

Key environment variables (see `env.example`):

- `PII_FIREWALL_KEY` – **required**, master key for AES-GCM.
- `PII_FIREWALL_DEFAULT_PROVIDER` – optional, e.g. `openai`.

Provider keys (at least one should be set):

- `OPENAI_API_KEY`, `OPENAI_MODEL`, `OPENAI_BASE_URL`
- `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`, `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_VERSION`
- `GEMINI_API_KEY`, `GEMINI_MODEL`, `GEMINI_BASE_URL`
- `DEEPSEEK_API_KEY`, `DEEPSEEK_MODEL`, `DEEPSEEK_BASE_URL`

If a provider’s key is missing, it simply won’t appear as “configured” in `/health` and `/whoami`, and the UI will either hide or de-emphasize it.

---

## 6. What to show in a demo / report

For a course demo or project report, a good flow is:

1. Start the server and open `http://127.0.0.1:8000/`.
2. Show `GET /whoami` in the browser or via `curl` to highlight which providers are configured.
3. In the UI:
   - pick a provider (e.g., OpenAI),
   - paste a prompt that includes email, phone, card, ID, and a secret,
   - show the PII panel lighting up,
   - expand the sanitized prompt (no raw PII),
   - then show the final reply with PII restored locally.
4. Optionally flip your balance to a provider with no credits to demonstrate the nice “insufficient balance” popup.
5. Finally, run a CLI example in the terminal to show the same pipeline without any web stack involved.

That’s usually enough to communicate both **security motivation** and **engineering design** to reviewers or TAs.

