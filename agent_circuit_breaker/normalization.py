"""Input normalization helpers for deterministic safety matching."""

from __future__ import annotations

import unicodedata


ZERO_WIDTH_CODEPOINTS = {
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero width no-break space / BOM
}


HOMOGLYPH_TRANSLATION = str.maketrans(
    {
        # Cyrillic lookalikes commonly usable in shell/SQL keywords.
        "А": "A",
        "В": "B",
        "С": "C",
        "Е": "E",
        "Н": "H",
        "І": "I",
        "К": "K",
        "М": "M",
        "О": "O",
        "Р": "P",
        "Т": "T",
        "Х": "X",
        "а": "a",
        "е": "e",
        "і": "i",
        "к": "k",
        "м": "m",
        "о": "o",
        "р": "p",
        "с": "c",
        "т": "t",
        "х": "x",
        "у": "y",
        # Greek lookalikes for the same narrow keyword-smuggling threat.
        "Α": "A",
        "Β": "B",
        "Ε": "E",
        "Η": "H",
        "Ι": "I",
        "Κ": "K",
        "Μ": "M",
        "Ν": "N",
        "Ο": "O",
        "Ρ": "P",
        "Τ": "T",
        "Χ": "X",
        "Υ": "Y",
        "Ζ": "Z",
        "α": "a",
        "β": "b",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "χ": "x",
        "υ": "y",
        "ζ": "z",
    }
)


def normalize_for_matching(value: str) -> str:
    """Return normalized text used by parsers and deterministic matchers."""
    if not isinstance(value, str):
        raise ValueError("Value must be a string")

    normalized = unicodedata.normalize("NFKC", value)
    normalized = "".join(
        char for char in normalized
        if char not in ZERO_WIDTH_CODEPOINTS and unicodedata.category(char) != "Cf"
    )
    return normalized.translate(HOMOGLYPH_TRANSLATION)
