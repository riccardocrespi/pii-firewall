# firewall/crypto.py

import os
import base64
from typing import Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# ---- Buckets: coarse length hiding per type ---- #

# You can tune these later
_DEFAULT_BUCKETS = [16, 32, 64, 128, 256]

TYPE_BUCKETS: Dict[str, list[int]] = {
    # short but sensitive
    "CARD": [16, 24, 32],
    "PHONE": [16, 24, 32],
    "ID": [16, 24, 32],
    # can be longer
    "EMAIL": [32, 64, 128],
    "ADDRESS": [64, 128, 256],
    "SECRET": [64, 128, 256],
    "OTHER_PII": [32, 64, 128],
}


def _choose_bucket(pii_type: str, n: int) -> int:
    buckets = TYPE_BUCKETS.get(pii_type, _DEFAULT_BUCKETS)
    for b in buckets:
        if n + 2 <= b:  # +2 for length prefix
            return b
    return buckets[-1]  # clamp to largest bucket


# ---- Key derivation ---- #

def _derive_type_key(master_key: bytes, pii_type: str) -> bytes:
    """
    Derive a per-type subkey from a master key using HKDF.
    Uses AES-256-GCM, so we need 32 bytes.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"pii-firewall:{pii_type}".encode("utf-8"),
    )
    return hkdf.derive(master_key)


# ---- Public API ---- #

def encrypt_pii(value: str, pii_type: str, master_key: bytes) -> str:
    """
    Encrypt a PII value with AES-GCM + padding.

    Returns a base64url-encoded string safe to place inside ⟦TYPE:...⟧.
    """
    if len(master_key) < 32:
        raise ValueError("master_key must be at least 32 bytes for AES-256-GCM")

    key = _derive_type_key(master_key, pii_type)
    aesgcm = AESGCM(key)

    plaintext_bytes = value.encode("utf-8")
    n = len(plaintext_bytes)
    bucket = _choose_bucket(pii_type, n)

    # 2 bytes for length (big-endian)
    if n > 65535:
        raise ValueError("PII value too long to encode length in 2 bytes")

    length_prefix = n.to_bytes(2, byteorder="big")

    pad_len = bucket - (2 + n)
    if pad_len < 0:
        # Should not happen because of _choose_bucket logic,
        # but check to be safe.
        raise RuntimeError("Bucket too small for plaintext")

    padding = os.urandom(pad_len)
    padded = length_prefix + plaintext_bytes + padding

    # 96-bit nonce is recommended for AES-GCM
    nonce = os.urandom(12)

    # Use pii_type as associated data (prevents type swapping)
    aad = pii_type.encode("utf-8")

    ciphertext = aesgcm.encrypt(nonce, padded, aad)

    # Output nonce || ciphertext as base64url
    token_bytes = nonce + ciphertext
    token_str = base64.urlsafe_b64encode(token_bytes).decode("ascii")

    return token_str


def decrypt_pii(token: str, pii_type: str, master_key: bytes) -> str:
    """
    Inverse of encrypt_pii. Takes base64url string, returns plaintext str.
    Raises if authentication fails.
    """
    if len(master_key) < 32:
        raise ValueError("master_key must be at least 32 bytes for AES-256-GCM")

    key = _derive_type_key(master_key, pii_type)
    aesgcm = AESGCM(key)

    token_bytes = base64.urlsafe_b64decode(token.encode("ascii"))

    if len(token_bytes) < 12 + 16:
        # 12-byte nonce + at least 16-byte GCM tag
        raise ValueError("Token too short to be valid")

    nonce = token_bytes[:12]
    ciphertext = token_bytes[12:]

    aad = pii_type.encode("utf-8")
    padded = aesgcm.decrypt(nonce, ciphertext, aad)

    if len(padded) < 2:
        raise ValueError("Decrypted data too short to contain length")

    n = int.from_bytes(padded[:2], byteorder="big")
    body = padded[2:]

    if len(body) < n:
        raise ValueError("Decrypted data shorter than declared length")

    plain_bytes = body[:n]
    return plain_bytes.decode("utf-8")
