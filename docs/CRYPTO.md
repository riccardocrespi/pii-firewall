# Crypto Design

This document describes the cryptographic design used by the PII Firewall.

---

## Goals

1. **Confidentiality**: PII should not be visible to external LLM providers.
2. **Integrity / authenticity**: any tampering with ciphertext should be detected.
3. **Local-only key**: encryption and decryption happen only on the client side.
4. **Reduced length leakage**: ciphertext length should reveal as little as reasonably possible about the plaintext length, while keeping the implementation simple enough for a course project.

We **do not** aim to:

- fully hide the **type** of PII (e.g., EMAIL vs CARD),
- achieve full format-preserving encryption (FPE) – we explicitly avoid exact length preservation.

---

## Overview

Each PII substring is:

1. Encrypted with **AES-256-GCM** using a per-type key derived from a master key.
2. Padded into a **bucketed length** before encryption to reduce length leakage.
3. Embedded in a token of the form:

   ```text
   ⟦TYPE:PAYLOAD⟧
   ```

   where:
   - `TYPE` is an uppercase label (e.g., `EMAIL`, `CARD`, etc.),
   - `PAYLOAD` is `base64url(nonce || ciphertext)`.

Tokens are inserted into the text by `sanitize()` and removed/decoded by `desanitize()`.

---

## Master key

- The master key is loaded from the environment via `PII_FIREWALL_KEY`.
- It must be at least **32 bytes** (for AES-256).
- It is represented as a UTF-8 string in the environment and converted to bytes in code.
- The key is **never** sent to the LLM provider.

In code:

```python
from firewall.config import get_master_key_from_env

master_key = get_master_key_from_env("PII_FIREWALL_KEY")
```

---

## Per-type keys (HKDF)

To limit the impact of key reuse across different PII types, a per-type key is derived from the master key using HKDF:

- HKDF with SHA-256 and 32-byte output.
- `info` parameter: `"pii-firewall:{TYPE}"`.

Conceptually:

```python
type_key = HKDF(
    algorithm=SHA256,
    length=32,
    salt=None,
    info=f"pii-firewall:{pii_type}".encode("utf-8"),
).derive(master_key)
```

This means:

- `EMAIL` and `CARD` use different keys, even if they share the same master key.
- Knowing the subkey for one type does not trivially give subkeys for others.

---

## Padding & length buckets

Plaintext PII values are padded into **buckets** to reduce length leakage.

For each PII type, we define a set of bucket sizes, e.g.:

```python
TYPE_BUCKETS = {
    "CARD": [16, 24, 32],
    "PHONE": [16, 24, 32],
    "EMAIL": [32, 64, 128],
    "ADDRESS": [64, 128, 256],
    "SECRET": [64, 128, 256],
    "OTHER_PII": [32, 64, 128],
}
```

Given a plaintext `value` and type `T`:

1. Encode `value` as UTF-8 → `plaintext_bytes`.
2. Let `n = len(plaintext_bytes)`.
3. Choose the smallest bucket `B` in `TYPE_BUCKETS[T]` such that `n + 2 <= B` (2 bytes for length).
4. Construct:

   ```text
   padded = [len_plain (2 bytes, big-endian)] + plaintext_bytes + random_pad
   ```

   where `len(padded) == B`.

If no bucket is large enough, we use the largest bucket (or raise an error, depending on implementation).

This scheme:

- ensures bounded length leakage (you can tell the bucket, not the exact length),
- keeps implementation relatively simple for a student project.

---

## AES-GCM encryption

We use AES-GCM (Galois/Counter Mode):

- Key: 32-byte per-type key (derived via HKDF).
- Nonce: 12 random bytes (`os.urandom(12)`).
- Associated Data (AAD): the PII type string (`pii_type.encode("utf-8")`).

Encryption:

```python
nonce = os.urandom(12)
aad = pii_type.encode("utf-8")
ciphertext = AESGCM(type_key).encrypt(nonce, padded, aad)
```

Output:

- Concatenate `nonce || ciphertext` and encode with base64url:

```python
token_bytes = nonce + ciphertext
token_str = base64.urlsafe_b64encode(token_bytes).decode("ascii")
```

This `token_str` is what goes inside the `⟦TYPE:...⟧` token.

---

## AES-GCM decryption

To decrypt:

1. Base64url-decode `token_str`:

   ```python
   token_bytes = base64.urlsafe_b64decode(token_str)
   ```

2. Split:

   - `nonce = token_bytes[:12]`
   - `ciphertext = token_bytes[12:]`

3. Use the *same* per-type key and AAD = type string:

   ```python
   padded = AESGCM(type_key).decrypt(nonce, ciphertext, aad)
   ```

4. Decode:

   - Check that `len(padded) >= 2`.
   - Extract `len_plain = int.from_bytes(padded[:2], "big")`.
   - Extract `plain_bytes = padded[2:2+len_plain]`.
   - Decode `plain_bytes` as UTF-8.

Any of the following will cause decryption to fail and raise `CryptoError`:

- invalid base64,
- incorrect nonce/ciphertext lengths,
- authentication failure (tampering, wrong key, wrong type / AAD),
- length field inconsistent with body,
- invalid UTF-8.

---

## Token structure

The sanitized text uses a **custom token format**:

```text
⟦TYPE:PAYLOAD⟧

TYPE    = uppercase label, e.g. EMAIL, CARD, SECRET, ...
PAYLOAD = base64url(nonce || AESGCM(type_key).encrypt(...))
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

## Error handling

All crypto errors are wrapped into `CryptoError` (a subclass of `FirewallError`):

- invalid or short master key,
- PII too long for the encoding scheme,
- malformed base64,
- short token bytes,
- AES-GCM authentication failures,
- invalid length field / truncated data,
- UTF-8 decode errors.

The app layer (CLI, FastAPI) can catch `FirewallError` / `CryptoError` and respond with appropriate error messages or HTTP status codes.

---

## Alternatives considered

### 1. Pure format-preserving encryption (FPE)

Early ideas considered format-preserving encryption (e.g. FF1/FF3 over digits) to keep card numbers or phone numbers looking like original formats.

Reasons we did **not** choose this:

- FPE preserves length and often structure, directly leaking more information.
- Implementations are more complex and require careful parameter choices to avoid subtle vulnerabilities.
- For a course project, integrating a full FPE library would make the crypto part heavier than needed.

Instead, we accept that tokens no longer resemble the original PII and focus on correctness, integrity, and reduced length leakage.

### 2. Simple reversible scheme (toy)

The project started with a trivial reversible scheme (string reversal) to validate the pipeline. This is still available as `crypto_simple.py` / `crypto_dummy.py` for tests or experimentation, but is **not** used in the main app.

---

## Security notes / limitations

- This design uses **standard building blocks**:
  - AES-256-GCM for authenticated encryption,
  - HKDF for key derivation.
- Bucketed padding reduces but does not eliminate length leakage.
- The threat model assumes:
  - the local environment is trusted,
  - the master key is not compromised,
  - the attacker may observe all traffic to/from the LLM provider.

Limitations:

- If the attacker compromises the local machine or obtains `PII_FIREWALL_KEY`, they can decrypt any tokens.
- Regex detection is imperfect; undetected PII will not be protected.
- Tokens themselves are clearly marked as special; an attacker can see **that** a sensitive field exists, only not what it contains.

For a production system, you would want:

- stronger key management (HSM, secret managers),
- more defense-in-depth around logs and backups,
- better and more comprehensive PII detection (including ML),
- formal review of crypto and implementation details.

---

## Summary

- AES-GCM provides confidentiality and integrity for each PII span.
- HKDF-derived per-type keys isolate different categories of PII.
- Bucketed padding reduces length leakage while staying relatively simple.
- Tokens encapsulate ciphertext in an LLM-friendly, opaque format that the provider cannot decode without the master key.

This is a **deliberate compromise** between practical implementation complexity and credible cryptographic behavior for a student-level project.
