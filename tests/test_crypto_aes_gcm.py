import base64

import pytest

from firewall.crypto_aes_gcm import encrypt_pii, decrypt_pii


# 32-byte demo master key (in real usage this comes from config/environment)
MASTER_KEY = b"0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize(
    "pii_type,value",
    [
        ("EMAIL", "john.doe@example.com"),
        ("CARD", "4111 1111 1111 1111"),
        ("PHONE", "+1 415 555 1234"),
        ("ADDRESS", "221B Baker Street, London"),
        ("SECRET", "AKIAIOSFODNN7EXAMPLE"),
    ],
)
def test_encrypt_decrypt_roundtrip(pii_type: str, value: str) -> None:
    token = encrypt_pii(value, pii_type, MASTER_KEY)

    # ciphertext should not equal plaintext
    assert token != value

    restored = decrypt_pii(token, pii_type, MASTER_KEY)
    assert restored == value


def test_tampering_is_detected() -> None:
    pii_type = "EMAIL"
    value = "john.doe@example.com"

    token = encrypt_pii(value, pii_type, MASTER_KEY)

    # decode, flip one bit, re-encode
    decoded = bytearray(base64.urlsafe_b64decode(token.encode("ascii")))
    decoded[-1] ^= 0x01
    tampered = base64.urlsafe_b64encode(bytes(decoded)).decode("ascii")

    # AES-GCM should detect tampering and raise
    with pytest.raises(Exception):
        decrypt_pii(tampered, pii_type, MASTER_KEY)


def test_per_type_keys_differ() -> None:
    """
    Same plaintext under different PII types should produce different ciphertext,
    because we derive a different key per type via HKDF.
    """
    value = "same-value"

    token_email = encrypt_pii(value, "EMAIL", MASTER_KEY)
    token_card = encrypt_pii(value, "CARD", MASTER_KEY)

    assert token_email != token_card

    # Both must still decrypt correctly under their own type
    assert decrypt_pii(token_email, "EMAIL", MASTER_KEY) == value
    assert decrypt_pii(token_card, "CARD", MASTER_KEY) == value
