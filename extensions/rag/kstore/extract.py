"""Document to normalized text + chunk sidecar (the shared corpus)."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .chunk import chunk_page
from .locator import Locator, line_at, sha256_file

PAGE_SEP = "\n\n"
FORM_FEED = "\x0c"
TEXT_SUFFIXES = {".txt", ".md", ".markdown", ".text"}
# OCR'd with tesseract (the `ocr` extension, which `rag` requires)
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".gif", ".webp"}


@dataclass(frozen=True)
class ExtractResult:
    doc_id: str
    out_dir: Path
    txt_path: Path
    chunks_path: Path
    meta_path: Path
    page_count: int
    empty_pages: list[int]
    chunk_count: int

    @property
    def needs_ocr(self) -> bool:
        return self.page_count > 0 and len(self.empty_pages) == self.page_count


def _pdf_pages(path: Path) -> list[str]:
    proc = subprocess.run(
        ["pdftotext", str(path), "-"],
        capture_output=True,
        text=True,
        check=True,
    )
    pages = proc.stdout.split(FORM_FEED)
    if pages and pages[-1] == "":
        pages.pop()
    return pages


def _image_text(path: Path) -> str:
    proc = subprocess.run(["tesseract", str(path), "-"], capture_output=True, text=True, check=True)
    return proc.stdout


def _doc_id(path: Path, digest: str | None = None) -> str:
    safe = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in path.stem)
    name = safe.strip("_") or "doc"
    short = (digest or sha256_file(path))[:8]
    return f"{name}-{short}"


def extract(
    source: Path,
    *,
    session_root: Path,
    out_root: Path,
    extractor: str | None = None,
    confidence: str = "high",
    target_chars: int | None = None,
    digest: str | None = None,
    origin: Path | None = None,
) -> ExtractResult:
    """Extract one document into the shared corpus. `origin`: the input file
    `source` was derived from (an OCR'd copy): locators, the doc id and the
    digest name the original, never the cache copy."""
    source = source.resolve()
    origin = origin.resolve() if origin is not None else source
    suffix = source.suffix.lower()
    if extractor is None:
        extractor = "pdftotext" if suffix == ".pdf" else "tesseract" if suffix in IMAGE_SUFFIXES else "text"
    if suffix in IMAGE_SUFFIXES and confidence == "high":
        confidence = "medium"  # OCR

    if suffix == ".pdf":
        pages = _pdf_pages(source)
    elif suffix in TEXT_SUFFIXES:
        pages = [source.read_text(encoding="utf-8", errors="replace")]
    elif suffix in IMAGE_SUFFIXES:
        pages = [_image_text(source)]
    else:
        raise ValueError(
            f"unsupported input for text extraction: {source.name} ({suffix}). "
            "For other media, transcribe it to a text file first."
        )

    try:
        rel_source = str(origin.relative_to(session_root.resolve()))
    except ValueError:
        rel_source = origin.name
    if digest is None:
        digest = sha256_file(origin)
    paged = suffix == ".pdf"

    full_parts: list[str] = []
    page_bases: list[int] = []
    cursor = 0
    empty_pages: list[int] = []
    for idx, raw in enumerate(pages, start=1):
        text = raw.rstrip()
        if not text.strip():
            empty_pages.append(idx)
        page_bases.append(cursor)
        full_parts.append(text)
        cursor += len(text) + len(PAGE_SEP)
    full_text = PAGE_SEP.join(full_parts)

    rows: list[dict] = []
    kwargs = {"target_chars": target_chars} if target_chars is not None else {}
    for idx, raw in enumerate(pages, start=1):
        page_text = raw.rstrip()
        base = page_bases[idx - 1]
        for span in chunk_page(page_text, **kwargs):
            g_start = base + span.start
            g_end = base + span.end
            loc = Locator(
                source_path=rel_source,
                sha256=digest,
                page_label=str(idx) if paged else None,
                char_start=g_start,
                char_end=g_end,
                line_start=line_at(full_text, g_start),
                line_end=line_at(full_text, g_end),
                extractor=extractor,
                confidence=confidence,
            )
            rows.append({"text": span.text, "locator": loc.to_dict()})

    doc_id = _doc_id(origin, digest)
    out_dir = out_root / doc_id
    out_dir.mkdir(parents=True, exist_ok=True)
    txt_path = out_dir / f"{doc_id}.txt"
    chunks_path = out_dir / f"{doc_id}.chunks.jsonl"
    meta_path = out_dir / f"{doc_id}.meta.json"

    txt_path.write_text(full_text, encoding="utf-8")
    with chunks_path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")

    result = ExtractResult(
        doc_id=doc_id,
        out_dir=out_dir,
        txt_path=txt_path,
        chunks_path=chunks_path,
        meta_path=meta_path,
        page_count=len(pages),
        empty_pages=empty_pages,
        chunk_count=len(rows),
    )
    meta_path.write_text(
        json.dumps(
            {
                "doc_id": doc_id,
                "source_path": rel_source,
                "sha256": digest,
                "extractor": extractor,
                "confidence": confidence,
                "page_count": result.page_count,
                "empty_pages": result.empty_pages,
                "needs_ocr": result.needs_ocr,
                "chunk_count": result.chunk_count,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return result
