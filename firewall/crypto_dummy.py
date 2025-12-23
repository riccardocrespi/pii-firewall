def dummy_encrypt(value: str, pii_type: str, key: bytes) -> str:
    """
    Dummy 'encryption' for now – just reverse the string.
    This is NOT secure; it's only to get the pipeline working.

    Later:
      - replace this with real format-preserving encryption
        per pii_type (digits-only, alnum, etc.).
    """
    return value[::-1]


def dummy_decrypt(ciphertext: str, pii_type: str, key: bytes) -> str:
    """Inverse of the dummy encrypt above."""
    return ciphertext[::-1]
