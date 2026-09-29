"""Corpus loaders producing records for BM25."""

from __future__ import annotations

from pathlib import Path

from . import paths
from .chunk import chunk_page
from .locator import line_at, sha256_file
from .rag import iter_corpus_records


def load_raw_records(extracted_root: Path) -> list[dict]:
    return list(iter_corpus_records(extracted_root))


def load_vault_records(vault_root: Path, *, session_root: Path) -> list[dict]:
    records: list[dict] = []
    wiki = vault_root / "wiki"
    base = wiki if wiki.is_dir() else vault_root
    for md in sorted(base.rglob("*.md")):
        text = md.read_text(encoding="utf-8", errors="replace")
        try:
            rel = str(md.relative_to(session_root))
        except ValueError:
            rel = md.name
        digest = sha256_file(md)
        for span in chunk_page(text):
            records.append(
                {
                    "text": span.text,
                    "locator": {
                        "source_path": rel,
                        "sha256": digest,
                        "page_label": None,
                        "char_start": span.start,
                        "char_end": span.end,
                        "line_start": line_at(text, span.start),
                        "line_end": line_at(text, span.end),
                        "extractor": "vault",
                        "confidence": "high",
                    },
                }
            )
    return records


def load_records(source: str, *, session_root: Path) -> list[dict]:
    if source == "raw":
        return load_raw_records(paths.corpus_dir(session_root))
    if source == "vault":
        return load_vault_records(paths.vault_dir(session_root), session_root=session_root)
    raise ValueError(f"unknown bm25 source: {source!r}")
