"""Shared llama_index plumbing for the RAG store."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from dataclasses import fields as _dc_fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .locator import Locator

LOCATOR_KEYS = tuple(f.name for f in _dc_fields(Locator))


_embed_singleton: Any = None


def _load_fastembed() -> Any:
    """fastembed's TextEmbedding, with onnxruntime's load-time probes quiet.

    onnxruntime reads /sys (CPU topology, GPUs) as it loads; the tool sandbox
    denies that and the C libraries print errors that are noise, not failures.
    Their stderr is kept back and shown only if loading fails."""
    import tempfile

    saved = os.dup(2)
    with tempfile.TemporaryFile() as held:
        os.dup2(held.fileno(), 2)
        try:
            import onnxruntime
            onnxruntime.set_default_logger_severity(3)  # errors only
            from fastembed import TextEmbedding
        except Exception:
            os.dup2(saved, 2)
            held.seek(0)
            os.write(2, held.read())
            raise
        finally:
            os.dup2(saved, 2)
            os.close(saved)
    return TextEmbedding


def make_embed():
    global _embed_singleton
    if _embed_singleton is not None:
        return _embed_singleton

    TextEmbedding = _load_fastembed()
    from llama_index.core.embeddings import BaseEmbedding
    from pydantic import PrivateAttr

    model_name = os.environ.get("KSTORE_EMBED_MODEL", "BAAI/bge-small-en-v1.5")
    cache_dir = os.environ.get("KSTORE_EMBED_CACHE")

    class _FastEmbed(BaseEmbedding):
        _model: Any = PrivateAttr()

        def __init__(self, **kw: Any) -> None:
            super().__init__(model_name=model_name, **kw)
            self._model = TextEmbedding(model_name=model_name, cache_dir=cache_dir)

        def _embed_docs(self, texts: list[str]) -> list[list[float]]:
            return [v.tolist() for v in self._model.embed(list(texts))]

        def _get_text_embedding(self, text: str) -> list[float]:
            return self._embed_docs([text])[0]

        def _get_text_embeddings(self, texts: list[str]) -> list[list[float]]:
            return self._embed_docs(texts)

        def _get_query_embedding(self, query: str) -> list[float]:
            return next(iter(self._model.query_embed([query]))).tolist()

        async def _aget_query_embedding(self, query: str) -> list[float]:
            return self._get_query_embedding(query)

    _embed_singleton = _FastEmbed()
    return _embed_singleton


def iter_corpus_records(extracted_root: Path) -> Iterator[dict]:
    for chunks_file in sorted(extracted_root.rglob("*.chunks.jsonl")):
        with chunks_file.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                yield json.loads(line)


def iter_corpus_nodes(extracted_root: Path) -> Iterator[Any]:
    from llama_index.core.schema import TextNode

    for row in iter_corpus_records(extracted_root):
        loc = row["locator"]
        node = TextNode(text=row["text"], metadata=dict(loc))
        node.excluded_embed_metadata_keys = list(LOCATOR_KEYS)
        node.excluded_llm_metadata_keys = list(LOCATOR_KEYS)
        yield node


def corpus_sources(extracted_root: Path) -> list[dict]:
    seen: dict[str, str] = {}
    for meta_file in sorted(extracted_root.rglob("*.meta.json")):
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        seen[meta.get("source_path", meta_file.stem)] = meta.get("sha256", "")
    return [{"source_path": k, "sha256": v} for k, v in seen.items()]


def write_manifest(persist_dir: Path, *, corpus: str, dim: int, chunk_count: int,
                   sources: list[dict]) -> None:
    (persist_dir / "manifest.json").write_text(
        json.dumps(
            {
                "corpus": corpus,
                "embed_model": os.environ.get("KSTORE_EMBED_MODEL", "BAAI/bge-small-en-v1.5"),
                "embed_base": os.environ.get("KSTORE_EMBED_BASE", ""),
                "dim": dim,
                "chunk_count": chunk_count,
                "sources": sources,
                "built_at": datetime.now(UTC).isoformat(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def read_manifest(persist_dir: Path) -> dict:
    p = persist_dir / "manifest.json"
    if not p.exists():
        raise SystemExit(f"kstore: no manifest at {p} — build the index first")
    return json.loads(p.read_text(encoding="utf-8"))


def assert_embed_matches(manifest: dict) -> None:
    want = os.environ.get("KSTORE_EMBED_MODEL", "BAAI/bge-small-en-v1.5")
    got = manifest.get("embed_model")
    if got != want:
        raise SystemExit(
            f"kstore: embed model mismatch — index built with '{got}', "
            f"current KSTORE_EMBED_MODEL='{want}'. Rebuild the index."
        )
