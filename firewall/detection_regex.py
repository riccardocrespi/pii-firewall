import re
import logging
from typing import List

from .spans import Span
from .errors import DetectionError

logger = logging.getLogger(__name__)


# -------------------- Regex-based detection -------------------- #
# v1: simple; we'll add ML later

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
)

PHONE_RE = re.compile(
    r"\+?\d[\d\-\s]{6,}\d"   # loose phone-like pattern
)

CARD_RE = re.compile(
    r"\b(?:\d[ -]*?){13,19}\b"  # 13–19 digits with spaces/dashes
)

ID_RE = re.compile(
    r"\b(?:\d{3}-\d{2}-\d{4}|[A-Z]{1,3}\d{6,9})\b"  # SSN-ish or passport-ish
)

SECRET_RE = re.compile(
    r"\b("
    r"sk-[A-Za-z0-9]{20,}"                           # OpenAI-style
    r"|AKIA[0-9A-Z]{16}"                             # AWS access key
    r"|ghp_[A-Za-z0-9]{20,}"                         # GitHub PAT
    r"|eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"  # JWT-ish
    r")\b"
)

ADDRESS_RE = re.compile(
    r"\b\d{1,5}\s+[A-Z][A-Za-z0-9.\s'-]{3,},?\s+[A-Z][A-Za-z.\s'-]{2,}\b"
    # e.g. "221B Baker Street, London"
)

OTHER_PII_RE = re.compile(
    r"\b("
    r"[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{0,2}"  # IBAN-ish
    r"|[A-Z]{1,3}\s?\d{1,4}\s?[A-Z]{1,3}"                      # license plate-ish
    r")\b"
)

# NAME is intentionally not handled by regex – we’ll let the model do that later.
NAME_RE = None


def _add_matches(pattern, pii_type: str, text: str, spans: List[Span]) -> None:
    if pattern is None:
        return
    for m in pattern.finditer(text):
        spans.append(Span(type=pii_type, start=m.start(), end=m.end()))


def detect_spans(text: str) -> List[Span]:
    """Regex-only detection v1. No ML yet."""
    try:
        spans: List[Span] = []

        _add_matches(EMAIL_RE, "EMAIL", text, spans)
        _add_matches(PHONE_RE, "PHONE", text, spans)
        _add_matches(CARD_RE, "CARD", text, spans)
        _add_matches(ID_RE, "ID", text, spans)
        _add_matches(SECRET_RE, "SECRET", text, spans)
        _add_matches(ADDRESS_RE, "ADDRESS", text, spans)
        _add_matches(OTHER_PII_RE, "OTHER_PII", text, spans)
        # _add_matches(NAME_RE, "NAME", text, spans)  # later with AI

        # sort + merge overlapping spans conservatively
        spans.sort(key=lambda s: (s.start, s.end))
        merged: List[Span] = []
        for s in spans:
            if not merged:
                merged.append(s)
                continue
            last = merged[-1]
            if s.start <= last.end:  # overlap or touch
                # extend last; keep its type (simple policy)
                last.end = max(last.end, s.end)
            else:
                merged.append(s)

        return merged

    except Exception as exc:
        # Should be very rare, but better to fail clearly
        logger.exception("Regex-based PII detection failed")
        raise DetectionError("Regex-based PII detection failed") from exc

