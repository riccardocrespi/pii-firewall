import logging
import re
from typing import List

from .spans import Span
from .detection_combined import detect_spans_combined
from .detection_regex import detect_spans as detect_spans_regex
# from .crypto_dummy import dummy_encrypt, dummy_decrypt
from .crypto_aes_gcm import encrypt_pii, decrypt_pii
from .errors import DetectionError, CryptoError, SanitizationError

logger = logging.getLogger(__name__)

# Token format: ⟦TYPE:PAYLOAD⟧
TOKEN_RE = re.compile(r"⟦([A-Z_]+):([^⟧]+)⟧")


def _detect_spans_with_fallback(text: str) -> List[Span]:
    """
    Try combined (regex + ML) detection first.
    If that fails for any reason, fall back to regex-only.
    """
    try:
        return detect_spans_combined(text)
    except Exception as exc:
        # If ML model isn't available / fails, log and fall back.
        logger.warning(
            "Combined PII detection failed, falling back to regex-only: %s", exc
        )
        try:
            return detect_spans_regex(text)
        except Exception as exc2:
            logger.exception("Regex-only PII detection also failed")
            raise DetectionError("PII detection failed") from exc2


def sanitize(text: str, key: bytes) -> str:
    """
    Replace sensitive spans with tokens of the form:

        ⟦TYPE:PAYLOAD⟧

    where PAYLOAD is ciphertext (AES-GCM + padding).
    """
    try:
        spans = _detect_spans_with_fallback(text)
        if not spans:
            return text

        # Ensure spans are sorted by start position
        spans = sorted(spans, key=lambda s: s.start)

        parts: List[str] = []
        last = 0

        for span in spans:
            # non-sensitive segment
            parts.append(text[last:span.start])

            # sensitive substring
            plain = text[span.start:span.end]

            # encrypt immediately
            ciph = encrypt_pii(plain, span.type, key)

            # embed in token; LLM should treat this as opaque
            token = f"⟦{span.type}:{ciph}⟧"
            parts.append(token)

            last = span.end

        parts.append(text[last:])
        return "".join(parts)

    except (DetectionError, CryptoError) as exc:
        # Known detection/crypto problems → wrap as SanitizationError
        raise SanitizationError("Failed to sanitize text") from exc
    except Exception as exc:
        logger.exception("Unexpected error in sanitize()")
        raise SanitizationError("Unexpected error in sanitize()") from exc


def desanitize(text: str, key: bytes, *, mode: str = "original") -> str:
    """
    Replace ⟦TYPE:PAYLOAD⟧ tokens:

    - mode="original": decrypt payload and put plaintext back
    - mode="encrypted": leave tokens as-is (no decryption)
    """

    def repl(m: re.Match) -> str:
        pii_type = m.group(1)
        payload = m.group(2)

        if mode == "encrypted":
            # keep token, user never sees plaintext
            return m.group(0)

        try:
            plain = decrypt_pii(payload, pii_type, key)
            return plain
        except CryptoError as exc:
            # Either keep token or surface an error; for now we surface an error
            raise SanitizationError(
                f"Failed to desanitize token of type {pii_type}"
            ) from exc

    try:
        return TOKEN_RE.sub(repl, text)
    except SanitizationError:
        # Already wrapped, just propagate
        raise
    except Exception as exc:
        logger.exception("Unexpected error in desanitize()")
        raise SanitizationError("Unexpected error in desanitize()") from exc
