# firewall/detection_combined.py

from typing import List

from .spans import Span
from .detection_regex import detect_spans as detect_spans_regex
from .ml_detector import MLDetector

# Load ML model once and reuse
_ml_detector = MLDetector()


def detect_spans_combined(text: str) -> List[Span]:
    """
    Combine regex-based spans with ML-based spans (BERT NER).
    """
    spans: List[Span] = []

    # 1) Regex spans: EMAIL, PHONE, CARD, SECRET, etc.
    spans.extend(detect_spans_regex(text))

    # 2) ML spans: NAME, ADDRESS, OTHER_PII
    spans.extend(_ml_detector.detect_spans(text))

    # 3) Sort + merge overlaps
    spans.sort(key=lambda s: (s.start, s.end))

    merged: List[Span] = []
    strong = {"EMAIL", "CARD", "SECRET", "PHONE", "ID"}  # regex “wins” for these

    for s in spans:
        if not merged:
            merged.append(s)
            continue

        last = merged[-1]
        if s.start <= last.end:
            # Overlap
            if last.type in strong and s.type not in strong:
                # keep last (regex span)
                continue
            if s.type in strong and last.type not in strong:
                # prefer new regex span
                merged[-1] = s
                continue

            # same strength: just extend the span
            last.end = max(last.end, s.end)
        else:
            merged.append(s)

    return merged
