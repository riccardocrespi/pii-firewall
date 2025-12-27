
# PII Firewall for LLM APIs

A local, privacy-preserving firewall that sits **in front of external LLM APIs**.

It:

- detects PII (emails, cards, IDs, secrets, names, addresses, etc.) using **regex + an ML NER model**,
- encrypts sensitive spans locally using **AES-GCM + padding**,
- replaces them with opaque tokens like `⟦EMAIL:…⟧`,
- forwards only the **sanitized** text to external LLM providers (OpenAI, Anthropic, Google Gemini, DeepSeek),
- restores the original plaintext locally in the reply.

The repository contains:

- a reusable Python library under `firewall/`,
- a CLI demo (`cli.py`),
- a FastAPI proxy (`api.py`) and a Tailwind-based web UI (`static/index.html`),
- tests and small evaluation corpora for the detector and crypto.

---

## Quick links

- [Architecture](docs/ARCHITECTURE.md) – high-level design, modules and data flow.
- [Crypto design](docs/CRYPTO.md) – AES-GCM scheme, padding, threat model.
- [ML / Inference](docs/INFERENCE.md) – NER model, normalization, combined detection.
- [Usage guide](docs/USAGE.md) – how to run the CLI, API, and web UI in practice.

---

## Features

- **Local-only crypto**
  - Master key never leaves your machine.
  - PII is always encrypted before leaving the local process.

- **Token-based sanitization**
  - Detected spans are replaced with tokens of the form `⟦TYPE:PAYLOAD⟧`.
  - `TYPE` describes the category (`EMAIL`, `CARD`, `NAME`, …).
  - `PAYLOAD` is AES-GCM ciphertext (with padding), safe to send to the LLM.

- **Hybrid detection**
  - `detection_regex.py` finds structured PII with regular expressions (emails, cards, AWS keys, IDs, etc.).
  - `ml_detector.py` uses a BERT NER model (`dslim/bert-base-NER`) to detect names and addresses, and some ORG entities.
  - `detection_combined.py` merges regex + ML spans, with conflict resolution (regex “wins” for strong types).

- **Multi-provider backend**
  - `providers.py` implements a unified interface for:
    - OpenAI / ChatGPT (`OPENAI_API_KEY`)
    - Anthropic / Claude (`ANTHROPIC_API_KEY`)
    - Google / Gemini (`GEMINI_API_KEY`)
    - DeepSeek (`DEEPSEEK_API_KEY`)

- **FastAPI proxy + Web UI**
  - `api.py` exposes:
    - `POST /v1/chat/completions` – OpenAI-style chat endpoint with an extra `provider` field.
    - `GET /health` – status and configured providers.
    - `GET /whoami` – configuration introspection.
  - `static/index.html` exposes a single-page UI:
    - provider selection + optional model override,
    - optional system prompt,
    - multi-turn chat (history kept in the browser),
    - PII type/count panel,
    - debug view: sanitized prompt + raw LLM reply,
    - final desanitized reply,
    - light/dark toggle,
    - reset chat,
    - modal popup when a provider returns “insufficient balance”.

- **Tests & evaluation data**
  - `tests/test_crypto_aes_gcm.py` – crypto roundtrip, tampering, wrong key/type.
  - `tests/test_detection_regex.py` – regression tests for regex patterns.
  - `tests/test_detection_combined.py` – sanity checks for ML+regex integration.
  - `tests/test_detection_evalset.py` – evaluation against `data/pii_eval_cases.yaml`.
  - `tests/test_sanitize_roundtrip.py` – end-to-end sanitize/desanitize.

---

## Repository layout

```text
pii-firewall/
├─ firewall/
│  ├─ __init__.py
│  ├─ spans.py                # Span dataclass (type, start, end)
│  ├─ errors.py               # FirewallError + Crypto/Detection/Sanitization errors
│  ├─ detection_regex.py      # Regex-based PII detection
│  ├─ ml_detector.py          # BERT-based ML detection (NAME, ADDRESS, etc.)
│  ├─ detection_combined.py   # Hybrid detector (regex + ML)
│  ├─ crypto_aes_gcm.py       # AES-GCM + padding, per-type keys
│  ├─ crypto_dummy.py         # Legacy / demo “dummy” crypto (reverse string)
│  ├─ sanitize.py             # sanitize() / desanitize() pipeline
│  ├─ client.py               # LLMFirewallClient wrapper
│  ├─ config.py               # Master key handling from env
│  ├─ providers.py            # OpenAI / Anthropic / Gemini / DeepSeek clients
│  └─ spans.py                # Span dataclass
│
├─ api.py                     # FastAPI proxy (HTTP API + serves web UI)
├─ cli.py                     # CLI that wraps an arbitrary LLM-like callable
├─ static/
│  └─ index.html              # Single-page Tailwind UI
├─ data/
│  ├─ pii_example_sentences.yaml  # Examples per PII type
│  └─ pii_eval_cases.yaml         # Detection evaluation cases
├─ tests/
│  ├─ test_crypto_aes_gcm.py
│  ├─ test_detection_regex.py
│  ├─ test_detection_combined.py
│  ├─ test_detection_evalset.py
│  └─ test_sanitize_roundtrip.py
├─ docs/
│  ├─ ARCHITECTURE.md
│  ├─ CRYPTO.md
│  ├─ INFERENCE.md
│  └─ USAGE.md
├─ env.example
├─ requirements.txt
├─ pytest.ini
└─ README.md
```

---

## Installation

```bash
git clone git@github.com:riccardocrespi/pii-firewall.git
cd pii-firewall

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create and edit `.env`:

```bash
cp env.example .env
```

Important variables:

- `PII_FIREWALL_KEY` – master key for AES-GCM (at least 32 bytes when UTF-8 encoded).
- `PII_FIREWALL_DEFAULT_PROVIDER` – optional (`openai`, `anthropic`, `google`, `deepseek`).
- Provider API keys as needed:
  - `OPENAI_API_KEY`
  - `ANTHROPIC_API_KEY`
  - `GEMINI_API_KEY`
  - `DEEPSEEK_API_KEY`

Load your `.env`:

```bash
set -a
source .env
set +a
```

---

## Running tests

```bash
source .venv/bin/activate
set -a; source .env; set +a

pytest -q
```

If you mark ML-heavy tests as `slow`, you can run:

```bash
pytest -m "not slow"   # fast subset
pytest -m slow         # only ML-heavy tests
```

---

## CLI usage

```bash
python cli.py "My email is john.doe@example.com and my card is 4111 1111 1111 1111."
```

The CLI prints:

1. sanitized prompt,
2. raw LLM reply (still containing tokens),
3. final reply (PII restored).

Encrypted-only mode:

```bash
python cli.py --mode encrypted "My phone is +1 415 555 1234."
```

Verbose mode:

```bash
python cli.py -v "Here is an AWS key AKIAIOSFODNN7EXAMPLE."
```

---

## FastAPI proxy

Start:

```bash
uvicorn api:app --reload
# or: uvicorn api:app --reload --env-file .env
```

Then open: `http://127.0.0.1:8000/`

You can:

- choose provider and optionally override the model,
- set a system prompt,
- chat in multiple turns,
- see detected PII types and counts,
- inspect sanitized prompt and raw LLM reply,
- see final desanitized reply,
- toggle light/dark mode and reset chat.

API endpoints:

- `GET /health` – status + configured providers.
- `GET /whoami` – introspection (master key present, default provider, etc.).
- `POST /v1/chat/completions` – OpenAI-style chat with `provider` field.

If a provider reports insufficient balance, the API returns HTTP 402 with a normalized JSON payload; the UI shows a modal popup and an inline error.

---

## Design docs

- [Architecture](docs/ARCHITECTURE.md)
- [Crypto design](docs/CRYPTO.md)
- [ML / Inference](docs/INFERENCE.md)
- [Usage guide](docs/USAGE.md)

---

## License

MIT License – see [LICENSE](LICENSE) for details.