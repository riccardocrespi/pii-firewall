# ML Inference & NER-based detection

This document describes how the ML-based detector in `firewall/ml_detector.py` works and how it is integrated with the regex-based detection.

## Overview

The ML detector uses **named entity recognition (NER)** to find entities that are hard to capture with regex alone:

- personal names (`NAME`),
- locations / addresses (`ADDRESS`),
- some organization identifiers (`OTHER_PII`).

It uses a HuggingFace `transformers` pipeline and is combined with regex detection in `detection_combined.py`.

## Model & pipeline

The detector uses:

- model: `dslim/bert-base-NER`
- task: `"token-classification"`
- aggregation strategy: `"simple"` (merge subword pieces into entities)

Initialization:

```python
self._pipe = pipeline(
    "token-classification",
    model=model_name,
    aggregation_strategy="simple",
)
```

Entities below a configurable confidence `threshold` (default 0.7) are discarded.

## Case normalization (`normalize_for_ner`)

Users can write text with arbitrary casing:

> "my name is tEODoro toSCano and i live near times square in new york."

To get better results from the NER model while preserving character indices, `normalize_for_ner()`:

- operates character-by-character,
- treats ASCII letters `[A-Za-z]` as words,
- uppercases the first letter of each word,
- lowercases the rest of the letters in the word,
- leaves non-letters unchanged.

Example:

- input: `"tEODoro toSCano"`
- normalized: `"Teodoro Toscano"`

Because normalization only changes letter case and never adds or removes characters, string length is preserved and the `start` / `end` offsets returned by the model still match the original text.

## Mapping NER groups to PII types

The model outputs entities with `entity_group` such as `PER`, `LOC`, `ORG`, `MISC`. These are mapped to firewall PII types:

- `PER` → `"NAME"`
- `LOC` → `"ADDRESS"`
- `ORG` → `"OTHER_PII"`
- anything else (e.g. `MISC`) is ignored.

Low-confidence entities (score < threshold) are dropped.

## Span construction and post-processing

The detector builds `Span` objects:

```python
Span(type=pii_type, start=ent["start"], end=ent["end"])
```

Then:

- sort spans by `(start, end)`,
- merge overlapping spans of the same type (extend `end`),
- keep different types separate (conflicts are resolved at the combined detection level).

The result is a list of `Span` objects compatible with the regex-based detector.

## Combined detection (`detection_combined.py`)

The combined detector coordinates regex + ML:

1. Run `detect_spans_regex(text)` for structured types (EMAIL, CARD, SECRET, etc.).
2. Run `MLDetector.detect_spans(text)` for NAME, ADDRESS, OTHER_PII.
3. Merge lists and sort by `(start, end)`.
4. Merge overlaps with precedence rules:
   - “strong” types (`EMAIL`, `CARD`, `SECRET`, `PHONE`, `ID`) from regex override weaker ML spans when overlapping.
   - equal-strength spans merge by extending the `end` index.

This gives a single list of spans that is then fed into `sanitize()`.

## Fallback behaviour

`sanitize()` calls `_detect_spans_with_fallback(text)`:

- first try `detect_spans_combined(text)`,
- if this throws (e.g. missing transformers, no GPU, model download issue), log a warning and fall back to `detect_spans_regex(text)`,
- if regex also fails, raise `DetectionError("PII detection failed")`.

This design keeps the ML detector as an enhancement: the firewall continues working with regex-only detection if ML is unavailable.

## Performance & lifecycle

The ML detector is instantiated once at module import time:

```python
_ml_detector = MLDetector()
```

So:

- long-lived processes like the FastAPI server pay the model load cost once,
- subsequent requests reuse the same pipeline object.

On development machines, the model might download the first time you run tests or start the server (depending on HuggingFace cache state).

## Testing & evaluation

ML-based detection and its integration are tested in:

- `tests/test_detection_combined.py` – sanity checks that typical sentences yield the right types.
- `tests/test_detection_evalset.py` – uses `data/pii_eval_cases.yaml` to verify that expected PII types are found in small evaluation cases.

Combined with regex tests and sanitize roundtrip tests, this gives a basic but practical level of regression coverage for the detector.

## Disabling ML detection

If you need a lightweight deployment:

- you can use regex-only detection by calling `detect_spans_regex()` directly, or
- you can modify `_detect_spans_with_fallback()` to skip the ML path and go straight to regex.

Because the modules are loosely coupled, you can remove or swap out the ML detector without changing the rest of the system.

## Future directions

Possible improvements:

- support multilingual NER models,
- add specialized models for other PII categories (DOB, usernames, etc.),
- train a custom model that directly predicts the PII taxonomy used by the firewall,
- support chunk-wise detection for very long inputs.

