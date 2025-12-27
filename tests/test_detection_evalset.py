from pathlib import Path
from typing import List

import pytest
import yaml

from firewall.detection_combined import detect_spans_combined


def _types_for(text: str) -> List[str]:
    spans = detect_spans_combined(text)
    return sorted({s.type for s in spans})


def _load_eval_cases():
    path = Path(__file__).parents[1] / "data" / "pii_eval_cases.yaml"
    if not path.exists():
        pytest.skip("pii_eval_cases.yaml not found")
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if not isinstance(data, list):
        pytest.skip("pii_eval_cases.yaml has unexpected structure")
    return data


@pytest.mark.slow
def test_eval_cases_cover_expected_types() -> None:
    cases = _load_eval_cases()
    assert cases, "No eval cases loaded"

    for i, case in enumerate(cases):
        text = case.get("text", "")
        expected_types = case.get("expected_types", [])
        detected = _types_for(text)

        # Every expected type should be present in detected
        for t in expected_types:
            assert t in detected, (
                f"Missing type {t} for case #{i}: {text!r}. "
                f"Detected types: {detected}"
            )

        # Optional: for empty expectations, assert we detect nothing
        if not expected_types:
            assert not detected, (
                f"Expected no PII, but detected {detected} "
                f"for text: {text!r}"
            )
