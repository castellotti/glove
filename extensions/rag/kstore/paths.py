"""Canonical on-disk layout of a kstore session."""

from __future__ import annotations

import os
from pathlib import Path


def session_root() -> Path:
    return Path(os.environ.get("KSTORE_SESSION_ROOT", "/work")).resolve()


DEFAULT_SESSION_ROOT = str(session_root())


def data_dir(sr: Path | None = None) -> Path:
    return (sr or session_root()) / "data"


def input_dir(sr: Path | None = None) -> Path:
    return data_dir(sr) / "input"


def output_dir(sr: Path | None = None) -> Path:
    return data_dir(sr) / "output"


def store_dir(sr: Path | None = None) -> Path:
    return data_dir(sr) / "store"


def corpus_dir(sr: Path | None = None) -> Path:
    return store_dir(sr) / "corpus"


def cache_dir(sr: Path | None = None) -> Path:
    return store_dir(sr) / "cache"


def vault_dir(sr: Path | None = None) -> Path:
    return store_dir(sr) / "vault"


def llama_dir(sr: Path | None = None) -> Path:
    return store_dir(sr) / "llama"


def compare_dir(sr: Path | None = None) -> Path:
    return store_dir(sr) / "compare"


def ledger_path(sr: Path | None = None) -> Path:
    return store_dir(sr) / "parsed.json"


def ensure_layout(sr: Path | None = None) -> None:
    for d in (input_dir(sr), output_dir(sr), corpus_dir(sr), cache_dir(sr),
              vault_dir(sr), llama_dir(sr), compare_dir(sr)):
        d.mkdir(parents=True, exist_ok=True)
