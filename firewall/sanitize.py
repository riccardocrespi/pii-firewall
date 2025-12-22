import re
from typing import List, Callable

from .spans import Span
# from .crypto_dummy import dummy_encrypt, dummy_decrypt
from .crypto_aes_gcm import encrypt_pii, decrypt_pii
#from .detection_regex import detect_spans
from .detection_combined import detect_spans_combined

TOKEN_RE = re.compile(r"⟦([A-Z_]+):([^⟧]+)⟧")

SpanDetector = Callable[[str], List[Span]]


def sanitize(text: str, key: bytes, detector: SpanDetector = detect_spans_combined) -> str:
    """
    Replace sensitive spans with tokens of the form:

        ⟦TYPE:PAYLOAD⟧

    where PAYLOAD is ciphertext. No mapping of plaintext is kept.
    """
    spans = detector(text)
    if not spans:
        return text

    spans = sorted(spans, key=lambda s: s.start)

    parts: List[str] = []
    last = 0

    for span in spans:
        # non-sensitive segment
        parts.append(text[last:span.start])

        # sensitive substring
        plain = text[span.start:span.end]

        # encrypt immediately
        # ciph = dummy_encrypt(plain, span.type, key)
        ciph = encrypt_pii(plain, span.type, key)

        # embed in token; LLM should treat this as opaque
        token = f"⟦{span.type}:{ciph}⟧"
        parts.append(token)

        # plaintext only lives in 'plain' local variable
        last = span.end

    parts.append(text[last:])
    return "".join(parts)


def desanitize(text: str, key: bytes, *, mode: str = "original") -> str:
    """
    Replace ⟦TYPE:PAYLOAD⟧ tokens:

    - mode="original": decrypt payload and put plaintext back
    - mode="encrypted": leave tokens as-is (no decryption)

    You can choose what you give back to the user / next system.
    """

    def repl(m: re.Match) -> str:
        pii_type = m.group(1)
        payload = m.group(2)

        if mode == "encrypted":
            # keep token, user never sees plaintext
            return m.group(0)

        # decrypt on the fly
        # plain = dummy_decrypt(payload, pii_type, key)
        plain = decrypt_pii(payload, pii_type, key)
        return plain

    return TOKEN_RE.sub(repl, text)
