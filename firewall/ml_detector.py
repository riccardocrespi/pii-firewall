"""
ML-based detector using a pretrained BERT NER model.

It finds entities (names, locations, orgs) and maps them into your PII
types so the existing sanitize() function can encrypt them.
"""
from typing import List, Optional

from transformers import pipeline
from .spans import Span


def normalize_for_ner(text: str) -> str:
    """
    Return a version of `text` where each word is put into 'Title' case
    (first letter uppercase, remaining letters lowercase), but:

      - we ONLY touch ASCII letters [A-Za-z]
      - we NEVER insert or delete characters

    This way the string length and all character indices stay exactly
    the same as in the original text, so the start/end offsets returned
    by the NER model are still valid on the original string.
    """
    chars = list(text)
    at_word_start = True

    for i, ch in enumerate(chars):
        # Restrict to basic Latin letters to avoid weird Unicode case folding
        is_ascii_letter = ("a" <= ch <= "z") or ("A" <= ch <= "Z")

        if is_ascii_letter:
            if at_word_start:
                # First letter of a word → uppercase
                chars[i] = ch.upper()
            else:
                # Non-first letter of a word → lowercase
                chars[i] = ch.lower()
            at_word_start = False
        else:
            # Treat whitespace and common punctuation as word boundaries
            if ch.isspace() or ch in "-_/\\,.!?;:()[]{}'\"":
                at_word_start = True
            else:
                # Non-letter, non-boundary: leave as-is, continue current word
                at_word_start = False

    return "".join(chars)


class MLDetector:
    """
    Wraps a pretrained NER model (dslim/bert-base-NER) and exposes
    detect_spans(text) -> List[Span] in your PII taxonomy.

    Model entity groups:
      - PER  -> NAME
      - LOC  -> ADDRESS  (rough, but useful)
      - ORG  -> OTHER_PII (or ignore if you don't want it)
    """

    def __init__(
        self,
        model_name: str = "dslim/bert-base-NER",
        threshold: float = 0.7,
    ) -> None:
        # aggregation_strategy="simple" merges tokens into entities with start/end offsets
        self._pipe = pipeline(
            "token-classification",
            model=model_name,
            aggregation_strategy="simple",
        )
        self.threshold = threshold

    def detect_spans(self, text: str) -> List[Span]:
        """
        Run NER on text and return PII spans in your format.

        We normalize casing (Title Case per word) before sending it to the NER
        model to improve detection for weird user casing like:

            "my name is JOhN dOe and i live in nEw yORk."

        The normalization only changes letter case, never length, so the
        offsets returned by the model are still valid on the original text.
        """
        text = text or ""
        if not text.strip():
            return []

        # Normalize text for NER, but keep length and indices identical
        norm_text = normalize_for_ner(text)

        raw_entities = self._pipe(norm_text)
        spans: List[Span] = []

        for ent in raw_entities:
            score = float(ent.get("score", 0.0))
            if score < self.threshold:
                continue

            group = ent.get("entity_group")  # e.g. "PER", "LOC", "ORG", "MISC"
            pii_type = self._map_entity_group(group)
            if pii_type is None:
                continue

            start = int(ent["start"])
            end = int(ent["end"])
            spans.append(Span(type=pii_type, start=start, end=end))

        # sort and merge overlapping spans of same type
        spans.sort(key=lambda s: (s.start, s.end))
        merged: List[Span] = []
        for s in spans:
            if not merged:
                merged.append(s)
                continue

            last = merged[-1]
            if s.start <= last.end and s.type == last.type:
                # extend existing span
                last.end = max(last.end, s.end)
            else:
                merged.append(s)

        return merged

    @staticmethod
    def _map_entity_group(group: Optional[str]) -> Optional[str]:
        """
        Map model entity group -> your PII types.
        """
        if group == "PER":
            return "NAME"
        if group == "LOC":
            return "ADDRESS"
        if group == "ORG":
            return "OTHER_PII"
        # ignore MISC or anything else for now
        return None


# Simple manual test: `python -m firewall.ml_detector`
if __name__ == "__main__":
    detector = MLDetector()
    text = "my name is tEODoro toSCano and i live near times square in new york."
    spans = detector.detect_spans(text)

    print("Text:", text)
    print("Detected spans:")
    for s in spans:
        print(
            f"  {s.type:<10} -> {repr(text[s.start:s.end])} "
        )
