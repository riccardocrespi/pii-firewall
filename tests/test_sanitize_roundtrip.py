import pytest
from pathlib import Path
import yaml

from firewall.sanitize import sanitize, desanitize


# 32-byte demo master key (same idea as in crypto tests)
MASTER_KEY = b"0123456789abcdef0123456789abcdef"


@pytest.mark.parametrize(
    "text",
    [
        # multiple types in one sentence
        "My email is john.doe@example.com and my card is 4111 1111 1111 1111.",
        # phone + address
        "Call me at +1 415 555 1234 and visit me at 221B Baker Street, London.",
        # secret-ish
        "Here is an AWS key AKIAIOSFODNN7EXAMPLE.",
        # mix with no PII at all
        "This string has no secrets, only boring words.",
    ],
)
def test_sanitize_desanitize_roundtrip(text: str) -> None:
    redacted = sanitize(text, MASTER_KEY)
    restored = desanitize(redacted, MASTER_KEY, mode="original")

    # Roundtrip should recover original text
    assert restored == text


def test_no_pii_text_is_unchanged_after_roundtrip() -> None:
    text = "Completely harmless text with no PII whatsoever."
    redacted = sanitize(text, MASTER_KEY)
    restored = desanitize(redacted, MASTER_KEY, mode="original")

    # sanitize may or may not change formatting, but there should be no tokens
    assert "⟦" not in redacted
    assert text == restored


def test_mode_encrypted_does_not_decrypt_tokens() -> None:
    text = "Contact me at john.doe@example.com"
    redacted = sanitize(text, MASTER_KEY)

    # Should contain at least one token
    assert "⟦EMAIL:" in redacted

    # With mode='encrypted', desanitize should leave tokens intact
    restored_encrypted = desanitize(redacted, MASTER_KEY, mode="encrypted")

    assert restored_encrypted == redacted

    # With mode='original', tokens are decrypted back to plaintext
    restored_plain = desanitize(redacted, MASTER_KEY, mode="original")
    assert restored_plain == text


def test_yaml_examples_roundtrip() -> None:
    """
    Load example sentences from data/pii_example_sentences.yaml and ensure
    sanitize + desanitize is a lossless roundtrip on all of them.

    YAML structure (current):
      NAME:
        - "My name is Alice Johnson."
        - ...
      EMAIL:
        - "My email is john.doe@example.com."
        - ...
      ...
    """
    path = Path(__file__).parents[1] / "data" / "pii_example_sentences.yaml"

    if not path.exists():
        pytest.skip("YAML examples file not found")

    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)

    texts: list[str] = []

    if isinstance(data, dict):
        # data = { "NAME": [...], "EMAIL": [...], ... }
        for category, sentences in data.items():
            if not isinstance(sentences, list):
                continue
            for s in sentences:
                if isinstance(s, str):
                    texts.append(s)
    elif isinstance(data, list):
        # fallback if structure changes in the future
        for item in data:
            if isinstance(item, str):
                texts.append(item)

    assert texts, "No example texts found in YAML file"

    for text in texts:
        redacted = sanitize(text, MASTER_KEY)
        restored = desanitize(redacted, MASTER_KEY, mode="original")
        assert restored == text
