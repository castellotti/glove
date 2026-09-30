"""`kstore sync` — incremental parse of input/ into both stores."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from . import paths, vaultpage
from .extract import IMAGE_SUFFIXES, TEXT_SUFFIXES, _doc_id, extract
from .locator import sha256_file

SUPPORTED = {".pdf", *TEXT_SUFFIXES, *IMAGE_SUFFIXES}


def _load_ledger(sr: Path) -> dict:
    p = paths.ledger_path(sr)
    if p.exists():
        return json.loads(p.read_text(encoding="utf-8"))
    return {"version": 1, "docs": {}}


def _save_ledger(sr: Path, ledger: dict) -> None:
    ledger["updated_at"] = datetime.now(UTC).isoformat()
    paths.ledger_path(sr).write_text(json.dumps(ledger, indent=2), encoding="utf-8")


def _ocr_if_possible(src: Path, sr: Path, digest: str) -> Path | None:
    if not shutil.which("ocrmypdf"):
        return None
    out = paths.cache_dir(sr) / "ocr" / f"{_doc_id(src, digest)}-ocr.pdf"
    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["ocrmypdf", "--skip-text", "--quiet", str(src), str(out)],
            check=True, capture_output=True, text=True,
        )
        return out
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def cmd_sync(args: argparse.Namespace) -> int:
    sr = Path(args.session_root).resolve()
    paths.ensure_layout(sr)
    ledger = _load_ledger(sr)
    docs = ledger.setdefault("docs", {})

    inputs = [p for p in sorted(paths.input_dir(sr).rglob("*"))
              if p.is_file() and p.suffix.lower() in SUPPORTED]
    present_rel: set[str] = set()

    added = changed = skipped = ocr_done = 0
    needs_ocr: list[str] = []

    for src in inputs:
        rel = str(src.relative_to(sr))
        present_rel.add(rel)
        sha = sha256_file(src)
        prior = docs.get(rel)
        if prior and prior.get("sha256") == sha and (paths.corpus_dir(sr) / prior["doc_id"]).exists():
            skipped += 1
            continue

        res = extract(src, session_root=sr, out_root=paths.corpus_dir(sr), digest=sha)
        if res.needs_ocr and src.suffix.lower() == ".pdf":
            ocr = _ocr_if_possible(src, sr, sha)
            if ocr is not None:
                pre_ocr_dir = res.out_dir
                # cite the original input, not the OCR'd copy in the cache
                res = extract(ocr, session_root=sr, out_root=paths.corpus_dir(sr),
                              extractor="ocrmypdf", confidence="medium", digest=sha, origin=src)
                if pre_ocr_dir != res.out_dir and pre_ocr_dir.exists():
                    shutil.rmtree(pre_ocr_dir)
                ocr_done += 1
            else:
                needs_ocr.append(rel)

        docs[rel] = {
            "sha256": sha,
            "doc_id": res.doc_id,
            "chunk_count": res.chunk_count,
            "needs_ocr": rel in needs_ocr,
            "parsed_at": datetime.now(UTC).isoformat(),
        }
        if prior:
            changed += 1
        else:
            added += 1

    pruned = 0
    for rel in list(docs):
        if rel not in present_rel:
            doc_id = docs[rel]["doc_id"]
            shutil.rmtree(paths.corpus_dir(sr) / doc_id, ignore_errors=True)
            del docs[rel]
            pruned += 1

    _save_ledger(sr, ledger)

    changed_any = (added + changed + pruned + ocr_done) > 0
    rc = 0
    if changed_any or args.force:
        from .build import build_index

        rc = build_index(sr, "raw")
        v_written, v_pruned = vaultpage.write_source_pages(sr)
        vault_note = f"vault pages {v_written} (-{v_pruned})"
    else:
        vault_note = "stores unchanged — skipped rebuild"

    print(
        f"kstore sync: +{added} new, ~{changed} changed, ={skipped} unchanged, "
        f"-{pruned} removed; OCR'd {ocr_done}; {vault_note}."
    )
    if needs_ocr:
        print("  ⚠ needs OCR (ocrmypdf unavailable) — install/enable it then re-sync:")
        for rel in needs_ocr:
            print(f"    - {rel}")
    return rc


def register(sub: argparse._SubParsersAction) -> None:
    s = sub.add_parser("sync", help="incrementally parse input/ into both stores (+prune)")
    s.add_argument("--session-root", default=paths.DEFAULT_SESSION_ROOT)
    s.add_argument("--force", action="store_true", help="rebuild stores even if nothing changed")
    s.set_defaults(func=cmd_sync)
