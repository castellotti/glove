"""Deterministic, page-bounded chunking with exact offsets."""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_TARGET_CHARS = 450
DEFAULT_MAX_CHARS = 700


@dataclass(frozen=True)
class Span:
    text: str
    start: int
    end: int


def _paragraph_spans(page_text: str) -> list[Span]:
    spans: list[Span] = []
    i = 0
    n = len(page_text)
    while i < n:
        while i < n and page_text[i].isspace():
            i += 1
        if i >= n:
            break
        start = i
        while i < n:
            nl = page_text.find("\n\n", i)
            if nl == -1:
                i = n
                break
            i = nl
            break
        end = i
        text = page_text[start:end].rstrip()
        if text:
            spans.append(Span(text=text, start=start, end=start + len(text)))
        i = end + 2
    return spans


def _hard_split(span: Span, max_chars: int) -> list[Span]:
    out: list[Span] = []
    text, base = span.text, span.start
    pos = 0
    while pos < len(text):
        window = text[pos : pos + max_chars]
        if pos + max_chars >= len(text):
            cut = len(text)
        else:
            cut = window.rfind("\n")
            if cut <= 0:
                cut = window.rfind(" ")
            if cut <= 0:
                cut = max_chars
            cut = pos + cut
        piece = text[pos:cut].rstrip()
        if piece:
            out.append(Span(text=piece, start=base + pos, end=base + pos + len(piece)))
        pos = cut
        while pos < len(text) and text[pos].isspace():
            pos += 1
    return out


def chunk_page(
    page_text: str,
    *,
    target_chars: int = DEFAULT_TARGET_CHARS,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> list[Span]:
    """Chunk one page's text into offset-bearing spans."""
    chunks: list[Span] = []
    buf: list[Span] = []
    buf_len = 0

    def flush() -> None:
        nonlocal buf, buf_len
        if not buf:
            return
        start = buf[0].start
        end = buf[-1].end
        chunks.append(Span(text=page_text[start:end].rstrip(), start=start, end=end))
        buf = []
        buf_len = 0

    for para in _paragraph_spans(page_text):
        para_len = para.end - para.start
        if para_len > max_chars:
            flush()
            chunks.extend(_hard_split(para, max_chars))
            continue
        if buf and buf_len + para_len > target_chars:
            flush()
        buf.append(para)
        buf_len += para_len
    flush()
    return [c for c in chunks if c.text.strip()]
