"""
ML-based detector using a pretrained BERT NER model.

It finds entities (names, locations, orgs) and maps them into your PII
types so the existing sanitize() function can encrypt them.
"""
from typing import List, Optional

from transformers import pipeline
from .spans import Span


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
        """
        text = text or ""
        if not text.strip():
            return []

        raw_entities = self._pipe(text)
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
    text = "My name is Alice Johnson and I live near Times Square in New York."
    spans = detector.detect_spans(text)

    print("Text:", text)
    print("Detected spans:")
    for s in spans:
        print(
            f"  {s.type:<10} -> {repr(text[s.start:s.end])} "
        )
