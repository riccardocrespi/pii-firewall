from firewall.detection_regex import detect_spans


def _types_for(text: str) -> list[str]:
    return [s.type for s in detect_spans(text)]


def test_detects_email_and_card_separately() -> None:
    text = "My email is john.doe@example.com and my card is 4111 1111 1111 1111."
    types = _types_for(text)

    assert "EMAIL" in types
    assert "CARD" in types
    # No SECRET here, etc.
    assert "SECRET" not in types


def test_card_not_misclassified_as_phone() -> None:
    text = "Use card 4111 1111 1111 1111 for the test."
    spans = detect_spans(text)

    card_spans = [s for s in spans if s.type == "CARD"]
    phone_spans = [s for s in spans if s.type == "PHONE"]

    assert len(card_spans) == 1, "Card number should be detected as CARD"
    assert len(phone_spans) == 0, "Card number must not be detected as PHONE"


def test_detects_phone_and_address() -> None:
    text = "Call me at +1 415 555 1234 and visit 221B Baker Street, London."
    types = _types_for(text)

    assert "PHONE" in types
    assert "ADDRESS" in types


def test_detects_secret_and_id() -> None:
    text = "My AWS key is AKIAIOSFODNN7EXAMPLE and my SSN is 123-45-6789."
    types = _types_for(text)

    assert "SECRET" in types
    assert "ID" in types
