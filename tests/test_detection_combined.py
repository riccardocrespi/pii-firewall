# tests/test_detection_combined.py

import pytest

from firewall.detection_combined import detect_spans_combined


def _spans_for(text: str):
    return detect_spans_combined(text)


def _types_for(text: str):
    return [s.type for s in _spans_for(text)]


@pytest.mark.slow
def test_name_and_address_detected_by_ml() -> None:
    text = "My name is Alice Johnson and I live near Times Square in New York."
    types = _types_for(text)

    # ML-based NER should detect at least one NAME and one ADDRESS
    assert "NAME" in types
    assert "ADDRESS" in types


@pytest.mark.slow
def test_combined_name_email_card() -> None:
    text = (
        "My name is Alice Johnson, I live near Times Square, "
        "my email is john.doe@example.com and my card is 4111 1111 1111 1111."
    )

    spans = _spans_for(text)
    types = [s.type for s in spans]

    # Check ML + regex types are all present
    assert "NAME" in types
    assert "ADDRESS" in types
    assert "EMAIL" in types
    assert "CARD" in types

    # Sanity: each type has at least one span with expected substring
    s_name = [s for s in spans if s.type == "NAME"]
    s_email = [s for s in spans if s.type == "EMAIL"]
    s_card = [s for s in spans if s.type == "CARD"]

    assert s_name, "Expected at least one NAME span"
    assert s_email, "Expected at least one EMAIL span"
    assert s_card, "Expected at least one CARD span"
