"""Deterministic Obsidian source-pages from the extracted corpus."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from . import paths

SOURCES_SUBDIR = ("wiki", "sources")


def _pages_dir(session_root: Path) -> Path:
    d = paths.vault_dir(session_root)
    for part in SOURCES_SUBDIR:
        d = d / part
    return d


def _page_markdown(meta: dict, text: str) -> str:
    fm = {
        "kind": "source",
        "source_path": meta.get("source_path"),
        "sha256": meta.get("sha256"),
        "pages": meta.get("page_count"),
        "extractor": meta.get("extractor"),
        "confidence": meta.get("confidence"),
        "chunk_count": meta.get("chunk_count"),
        "parsed_at": datetime.now(UTC).isoformat(),
    }
    lines = ["---"]
    for k, v in fm.items():
        lines.append(f"{k}: {json.dumps(v) if v is not None else 'null'}")
    lines.append("---")
    title = Path(meta.get("source_path", meta.get("doc_id", "source"))).name
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"> Source: `{meta.get('source_path')}` · sha256 `{(meta.get('sha256') or '')[:12]}` "
                 f"· {meta.get('page_count')} page(s)")
    lines.append("")
    lines.append(text.rstrip())
    lines.append("")
    return "\n".join(lines)


def write_source_pages(session_root: Path) -> tuple[int, int]:
    corpus = paths.corpus_dir(session_root)
    pages_dir = _pages_dir(session_root)
    pages_dir.mkdir(parents=True, exist_ok=True)

    current: dict[str, dict] = {}
    for meta_file in sorted(corpus.rglob("*.meta.json")):
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        current[meta["doc_id"]] = meta

    written = 0
    for doc_id, meta in current.items():
        txt_path = corpus / doc_id / f"{doc_id}.txt"
        text = txt_path.read_text(encoding="utf-8") if txt_path.exists() else ""
        (pages_dir / f"{doc_id}.md").write_text(_page_markdown(meta, text), encoding="utf-8")
        written += 1

    pruned = 0
    for md in pages_dir.glob("*.md"):
        if md.stem not in current:
            md.unlink()
            pruned += 1
    return written, pruned
