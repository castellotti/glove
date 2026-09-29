"""kstore command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, paths


def cmd_extract(args: argparse.Namespace) -> int:
    from .extract import extract

    session_root = Path(args.session_root).resolve()
    out_root = Path(args.out_root).resolve() if args.out_root else paths.corpus_dir(session_root)

    sources: list[Path] = []
    for raw in args.sources:
        p = Path(raw)
        if p.is_dir():
            sources.extend(sorted(q for q in p.rglob("*") if q.is_file()))
        else:
            sources.append(p)
    if not sources:
        print("kstore extract: no input files", file=sys.stderr)
        return 2

    failures = 0
    for src in sources:
        try:
            res = extract(
                src,
                session_root=session_root,
                out_root=out_root,
                extractor=args.extractor,
                confidence=args.confidence,
                target_chars=args.target_chars,
            )
        except ValueError as exc:
            print(f"SKIP  {src}: {exc}", file=sys.stderr)
            failures += 1
            continue
        except FileNotFoundError as exc:
            print(f"ERROR {src}: {exc}", file=sys.stderr)
            failures += 1
            continue
        note = "  ⚠ needs OCR (all pages empty)" if res.needs_ocr else ""
        empty = f" empty={res.empty_pages}" if res.empty_pages and not res.needs_ocr else ""
        print(
            f"OK    {res.doc_id}: {res.page_count} page(s), "
            f"{res.chunk_count} chunk(s){empty} → {res.out_dir}{note}"
        )
    return 1 if failures else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kstore", description="glove rag knowledge-store tools")
    parser.add_argument("--version", action="version", version=f"kstore {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    ex = sub.add_parser("extract", help="normalize a document to text + chunk locators")
    ex.add_argument("sources", nargs="+", help="file(s) or directory(ies) to extract")
    ex.add_argument("--session-root", default=paths.DEFAULT_SESSION_ROOT, help="session root (=/work)")
    ex.add_argument("--out-root", default=None, help="output root (default: <session>/data/output/extracted)")
    ex.add_argument("--extractor", default=None, help="override extractor label (pdftotext|ocrmypdf|vision|text)")
    ex.add_argument("--confidence", default="high", choices=["high", "medium", "low"])
    ex.add_argument("--target-chars", type=int, default=None, help="target chunk size in characters")
    ex.set_defaults(func=cmd_extract)

    for module in ("sync", "build", "ask", "compare"):
        # llama_index/fastembed are imported lazily inside the commands
        __import__(f"kstore.{module}", fromlist=["register"]).register(sub)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
