"""The canonical locator — source-traceability contract for every chunk."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Locator:
    source_path: str
    sha256: str
    page_label: str | None
    char_start: int
    char_end: int
    line_start: int
    line_end: int
    extractor: str
    confidence: str

    def to_dict(self) -> dict:
        return asdict(self)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def line_at(text: str, char_index: int) -> int:
    if char_index <= 0:
        return 1
    return text.count("\n", 0, char_index) + 1


CITATION_KEYS = ("source_path", "page_label", "char_start", "char_end", "line_start", "line_end")


def citation_base(loc: dict) -> dict:
    return {k: loc.get(k) for k in CITATION_KEYS}


def format_citation(c: dict) -> str:
    loc = c["source_path"]
    if c.get("page_label"):
        loc += f" p{c['page_label']}"
    loc += f" [{c['char_start']}:{c['char_end']}] L{c['line_start']}-{c['line_end']}"
    return loc


def snippet(text: str | None, max_len: int = 200) -> str:
    return " ".join((text or "").split())[:max_len]
