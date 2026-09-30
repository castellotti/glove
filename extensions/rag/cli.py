"""`glove rag fetch-model` — download the session's embedding model to `models_dir`.

The session never has network for this (kstore embeds in-process, offline), so
the model is fetched once on the host, into the directory the `rag` extension
then mounts read-only.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import typer
from rich.console import Console

from glove import sessiondir as sdm
from glove.config import ConfigError
from glove.extensions import discover, validate_settings
from glove.mounts import host_path

app = typer.Typer(add_completion=False, help="Offline RAG (kstore): host-side helpers.")
err = Console(stderr=True)

DIR_OPT = typer.Option(None, "--dir", help="session directory (default: the nearest one)")
# the version the extension bakes into the harness image (extension.yml)
FASTEMBED = "fastembed==0.8.1"


def rag_settings(directory: Path | None) -> tuple[Path, str]:
    """(models_dir resolved on the host, embed_model) from the session file."""
    try:
        sd = sdm.find(directory)
        raw = sdm.load_file(sd)
    except sdm.SessionError as e:
        err.print(f"[red]error:[/red] {e}")
        raise typer.Exit(1) from e
    rag = (raw.get("extensions") or {}).get("rag")
    try:
        settings = validate_settings(discover()["rag"], rag if isinstance(rag, dict) else {})
    except ConfigError as e:
        err.print(f"[red]error:[/red] {sd.file}: {e} (set `extensions: {{rag: {{models_dir: <dir>}}}}`)")
        raise typer.Exit(1) from e
    return host_path(sd.root, settings["models_dir"]), settings["embed_model"]


@app.command("fetch-model")
def fetch_model(directory: Path | None = DIR_OPT) -> None:
    """Download the embedding model into the session's `models_dir` (needs internet once)."""
    models, model = rag_settings(directory)
    models.mkdir(parents=True, exist_ok=True)
    err.print(f"fetching fastembed model {model} → {models}")
    code = ("import sys; from fastembed import TextEmbedding; "
            "TextEmbedding(model_name=sys.argv[1], cache_dir=sys.argv[2]); print('cached', sys.argv[1])")
    r = subprocess.run(["uv", "run", "--quiet", "--no-project", "--python", "3.12", "--with", FASTEMBED,
                        "--", "python", "-c", code, model, str(models)])
    raise typer.Exit(r.returncode)
