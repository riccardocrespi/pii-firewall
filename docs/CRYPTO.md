# Crypto design

This document explains the cryptographic design implemented in `firewall/crypto_aes_gcm.py` and how it is used by the sanitization pipeline.

## Goals

- Ensure that **raw PII never leaves the local process** in plaintext.
- Provide **semantic security** for sensitive spans using AEAD (AES‑GCM).
- Limit **length leakage** via padding buckets.
- Prevent **type swapping** (e.g. reusing an `EMAIL` ciphertext as a `CARD`).
- Keep a simple token format that is easy to test and debug.

## Token format

Sanitization replaces PII substrings with tokens of the form:

```text
⟦TYPE:PAYLOAD⟧
```

- `TYPE`: plaintext label (e.g. `EMAIL`, `CARD`, `NAME`, `ADDRESS`).
- `PAYLOAD`: base64url-encoded `nonce || ciphertext`, where `ciphertext` is AES‑GCM over a padded plaintext.

PII values are never logged or sent to external LLMs in plaintext.

## Master key and per-type subkeys

The crypto layer expects a **master key**:

- loaded from `PII_FIREWALL_KEY` via `get_master_key_from_env()`,
- at least 32 bytes when UTF‑8 encoded (for AES‑256‑GCM).

For each PII type we derive a 32‑byte subkey using HKDF:

```python
HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=f"pii-firewall:{pii_type}".encode("utf-8"),
)
```

This isolates key material across PII types.


## Padding & buckets

To reduce length leakage, the plaintext is padded into **buckets**.

Plaintext layout inside AES‑GCM:

```text
[ 2-byte length prefix ][ UTF-8 plaintext ][ random padding ]
```

- The first 2 bytes store `n = len(plaintext_bytes)` in big-endian.
- The rest is random bytes so that the total padded length fits into a bucket.

Buckets per type (simplified):

```python
_DEFAULT_BUCKETS = [16, 32, 64, 128, 256]

TYPE_BUCKETS = {
    "CARD":     [16, 24, 32],
    "PHONE":    [16, 24, 32],
    "ID":       [16, 24, 32],
    "EMAIL":    [32, 64, 128],
    "ADDRESS":  [64, 128, 256],
    "SECRET":   [64, 128, 256],
    "OTHER_PII":[32, 64, 128],
}
```

For each `(pii_type, n)` pair, `_choose_bucket()` picks the smallest bucket `B` with `2 + n ≤ B`. Any leftover is filled with `os.urandom` bytes.

This reduces, but does not eliminate, information leakage from the ciphertext length. Buckets are tuned per type and can be adjusted.


## AES‑GCM API

The module exposes:

```python
encrypt_pii(value: str, pii_type: str, master_key: bytes) -> str
decrypt_pii(token: str, pii_type: str, master_key: bytes) -> str
```

### Encryption

1. Check master key length (≥ 32 bytes).
2. Derive per‑type key with HKDF.
3. Encode `value` as UTF‑8.
4. Build the padded plaintext as described above.
5. Generate a 12‑byte random nonce (`os.urandom(12)`).
6. Set AAD = `pii_type.encode("utf-8")` (associated data).
7. Compute `ciphertext = AESGCM(key).encrypt(nonce, padded, aad)`.
8. Concatenate `nonce || ciphertext` and base64url‑encode to ASCII.

The returned string is what appears in `⟦TYPE:PAYLOAD⟧`.


### Decryption

1. Check master key length and derive the same per‑type key.
2. Base64url‑decode the token and split `nonce` and `ciphertext`.
3. Call `AESGCM(key).decrypt(nonce, ciphertext, aad)` with the same AAD.
   - On authentication failure, raise `CryptoError("Failed to decrypt PII value (authentication failed)")`.
4. Parse the decrypted padded bytes:
   - first 2 bytes → `n`,
   - next `n` bytes → the plaintext,
   - the rest is padding and is discarded.
5. Decode the plaintext bytes as UTF‑8 and return the resulting string.

## Type binding and tamper resistance

Using `pii_type` as AAD binds ciphertext to its type:

- A token encrypted as `TYPE="EMAIL"` cannot be successfully decrypted as `TYPE="CARD"`, because the AAD differs.
- Any attempt at type swapping yields an authentication failure in AES‑GCM.

This is a simple but effective defense against cross‑type reuse of ciphertexts.


## Error handling

All crypto failures raise a `CryptoError`:

- invalid master key,
- base64 decoding errors,
- AES‑GCM authentication failure,
- malformed decrypted data (too short, bad length prefix, invalid UTF‑8).

The sanitization layer catches `CryptoError` and wraps it into `SanitizationError` where appropriate, so application code can treat the whole pipeline as a single black box.


## Integration with sanitize()/desanitize()

The sanitization functions are defined in `sanitize.py`:

- `sanitize(text, key)`:
  - runs detection to obtain spans (`Span(type, start, end)`),
  - slices the text at those spans,
  - replaces each span with `⟦TYPE:encrypt_pii(span_text, TYPE, key)⟧`.

- `desanitize(text, key, mode="original")`:
  - in `"original"` mode, finds tokens with a regex and calls `decrypt_pii()` for each,
  - in `"encrypted"` mode, leaves tokens as-is.

If token decryption fails, `desanitize()` raises `SanitizationError`; callers can decide whether to propagate, mask, or log these failures.


## Dummy crypto

`crypto_dummy.py` contains `dummy_encrypt()` / `dummy_decrypt()` that simply reverse the string. This is only used in tests or experiments and is **not** used in the production pipeline.


## Threat model

This design aims to:

- keep PII encrypted whenever it leaves the local machine,
- avoid unauthenticated encryption,
- prevent simple replay/type-swapping of ciphertext across PII categories,
- limit, though not fully eliminate, information leaked through ciphertext length.

Out of scope (for now):

- key management at scale (KMS, rotation),
- side-channel attacks (timing, cache),
- sophisticated traffic analysis beyond padding buckets.

These can be addressed in future iterations based on deployment needs.

