# PII Firewall for LLM APIs

A local, privacy-preserving firewall that sits **in front of untrusted LLM APIs**.

It:

- detects PII (emails, cards, IDs, secrets, etc.) using regex (ML pluggable later),
- encrypts sensitive spans locally using **AES-GCM + padding**,
- replaces them with opaque tokens like `⟦EMAIL:...⟧`,
- forwards only the **sanitized** text to external LLM providers (OpenAI, Anthropic, Gemini, DeepSeek),
- optionally restores the original plaintext locally in the reply.

This repo contains:

- a reusable Python library (`firewall/`)
- a CLI demo (`cli.py`)
- a FastAPI proxy (`api.py`) that can act as a local LLM gateway.

---

## Features

- 🔐 **Local encryption only** – master key never leaves your machine.
- 🧩 **Tokenized PII** – sensitive substrings replaced by `⟦TYPE:PAYLOAD⟧`.
- 🧱 **Layered architecture**:
  - detection → crypto → sanitize/desanitize → client → providers → proxy.
- 🔌 **Multi-provider support** (behind a common interface):
  - OpenAI / ChatGPT
  - Anthropic / Claude
  - Google / Gemini
  - DeepSeek
- ✅ **Tests** for:
  - AES-GCM crypto (roundtrip, tampering, wrong key/type),
  - sanitize/desanitize (including YAML example corpus).

ML-based detection (BERT-like NER for names) is designed to be plugged in later but is not yet implemented.

---

## Repository structure

```text
pii-firewall/
├─ firewall/
│  ├─ __init__.py
│  ├─ spans.py              # Span dataclass
│  ├─ detection_regex.py    # Regex-based PII detection
│  ├─ crypto_aes_gcm.py     # AES-GCM + padding crypto (used in production)
│  ├─ crypto_simple.py      # Legacy/simple reversible scheme (for experiments)
│  ├─ crypto_dummy.py       # Placeholder / test helpers (if used)
│  ├─ sanitize.py           # sanitize() / desanitize() pipeline
│  ├─ client.py             # LLMFirewallClient wrapper
│  ├─ config.py             # Env-based configuration (master key)
│  ├─ errors.py             # FirewallError, CryptoError, etc.
│  └─ providers.py          # OpenAI, Anthropic, Gemini, DeepSeek clients
│
├─ api.py                   # FastAPI proxy app
├─ cli.py                   # CLI demo (local firewall wrapper)
├─ data/
│  └─ pii_example_sentences.yaml   # Example sentences for tests
├─ tests/
│  ├─ test_crypto_aes_gcm.py
│  ├─ test_sanitize_roundtrip.py
│  └─ ... (possibly more)
├─ docs/
│  ├─ ARCHITECTURE.md
│  └─ CRYPTO.md
├─ .env.example             # Example configuration (copy to .env)
├─ .gitignore
├─ pytest.ini
├─ requirements.txt
└─ README.md
```

---

## Requirements

- Python 3.10+ (3.11 recommended)
- A virtual environment (optional but recommended)
- For provider access:
  - OpenAI: `OPENAI_API_KEY`
  - Anthropic: `ANTHROPIC_API_KEY` (optional)
  - Gemini: `GEMINI_API_KEY` (optional)
  - DeepSeek: `DEEPSEEK_API_KEY` (optional)

Python dependencies (see `requirements.txt`):

- `fastapi`
- `uvicorn[standard]`
- `httpx`
- `cryptography`
- `pyyaml`
- `pytest`
- `python-dotenv` (if using `--env-file`)

---

## Setup

Clone the repo and create a virtualenv:

```bash
git clone git@github.com:YOUR_USER/pii-firewall.git
cd pii-firewall

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

Copy the example environment file and edit it:

```bash
cp .env.example .env
```

Edit `.env` with your values (especially `PII_FIREWALL_KEY` and any provider API keys).

Load the `.env` into your shell:

```bash
set -a
source .env
set +a
```

You can check that important vars are visible:

```bash
python -c "import os; print(os.getenv('PII_FIREWALL_KEY') is not None, os.getenv('OPENAI_API_KEY') is not None)"
```

---

## Running tests

```bash
source .venv/bin/activate
set -a; source .env; set +a   # ensures env vars are available if needed

pytest -q
```

---

## CLI usage

The CLI wraps a fake LLM to demonstrate the firewall:

```bash
source .venv/bin/activate
set -a; source .env; set +a

python cli.py "My email is john.doe@example.com and my card is 4111 1111 1111 1111."
```

Output (structure):

- Original user input
- Sanitized prompt sent to (fake) LLM
- Raw LLM reply (contains tokens)
- Final reply presented to user (PII restored by desanitize)

To keep replies encrypted (tokens not decoded):

```bash
python cli.py --mode encrypted "My phone is +1 415 555 1234."
```

For debug logs:

```bash
python cli.py -v "Here is an AWS key AKIAIOSFODNN7EXAMPLE."
```

---

## FastAPI proxy

The proxy exposes a small OpenAI-like endpoint plus health endpoints.

### Run the server

With `.env` in place and loaded (or using `--env-file`):

```bash
source .venv/bin/activate

# Option 1: env already loaded via `source .env`
uvicorn api:app --reload

# Option 2: let uvicorn load .env
# uvicorn api:app --reload --env-file .env
```

Server starts at `http://127.0.0.1:8000`.

### Health & introspection

Check configuration:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/whoami
```

Interactive docs:

- Open `http://127.0.0.1:8000/docs` in your browser.

### Chat endpoint

`POST /v1/chat/completions`

Request shape (similar to OpenAI, with an extra `provider` field):

```json
{
  "provider": "openai",
  "messages": [
    {"role": "user", "content": "My email is john.doe@example.com and my card is 4111 1111 1111 1111. Please summarize."}
  ]
}
```

Example `curl`:

```bash
curl -X POST http://127.0.0.1:8000/v1/chat/completions   -H "Content-Type: application/json"   -d '{
    "provider": "openai",
    "messages": [
      {
        "role": "user",
        "content": "My email is john.doe@example.com and my card is 4111 1111 1111 1111. Please summarize."
      }
    ]
  }'
```

Response:

```json
{
  "sanitized_prompt": "USER: My email is ⟦EMAIL:...⟧ and my card is ⟦CARD:...⟧. Please summarize.",
  "raw_llm_reply": "...reply text with tokens...",
  "final_reply": "...reply text with original email and card restored..."
}
```

Supported `provider` values:

- `"openai"`
- `"anthropic"`
- `"google"` (Gemini)
- `"deepseek"`

Only providers with API keys set in environment will be usable. `/health` and `/whoami` show which ones are configured.

---

## Threat model (high level)

- The LLM provider **never sees raw PII**; it only sees tokens like `⟦TYPE:BASE64⟧`.
- Encryption (AES-GCM) and decryption happen **locally**, using a master key loaded from `PII_FIREWALL_KEY`.
- Length leakage is reduced (but not eliminated) via **bucketed padding**.
- Integrity is enforced: tampering with ciphertext causes decryption to fail.

For more detail, see `docs/CRYPTO.md`.

---

## Roadmap / Future work

- 🔠 ML / BERT-like detector for names and less structured PII.
- 🎛 Configurable policies:
  - which PII types to mask
  - per-type modes (`original` vs `encrypted`).
- 📡 Streaming support (proxying SSE / streaming responses).
- 📊 Debug UI that visualizes detected spans & tokens.

---

## Limitations

- Detection is currently **regex-based only** (no ML yet), so:
  - some PII may not be detected,
  - some non-PII text may be detected (false positives).
- The proxy does not attempt to **rewrite** model outputs beyond token desanitization.
- Bucketed padding leaks approximate length; this is a trade-off between complexity and privacy for a course project.

---

## License

TBD (choose MIT / Apache-2.0 / etc. depending on course requirements).
