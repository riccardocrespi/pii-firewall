from dataclasses import dataclass


@dataclass
class Span:
    type: str   # e.g. "EMAIL", "CARD"
    start: int  # character offset in the string (inclusive)
    end: int    # character offset (exclusive)
