"""`kstore ask` — unified retrieval behind /skill:rag-query."""

from __future__ import annotations

import argparse
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from . import compare, paths
from .locator import citation_base, format_citation, snippet

DEFAULT_STORES = os.environ.get("KSTORE_QUERY_STORES", "both")


def _resolve_stores(arg: str) -> list[str]:
    val = (arg or DEFAULT_STORES).strip().lower()
    if val == "both":
        return ["obsidian", "llama"]
    return [s.strip() for s in val.split(",") if s.strip()]


def _retrieve(sr: Path, store: str, question: str, k: int, obsidian_source: str):
    if store == "llama":
        return compare.retrieve_llama(sr, "raw", question, k)
    if store == "obsidian":
        return compare.retrieve_bm25(sr, obsidian_source, question, k)
    raise SystemExit(f"kstore ask: unknown store '{store}' (use obsidian|llama|both)")


def _key(loc: dict) -> tuple:
    return (loc.get("source_path"), loc.get("char_start"), loc.get("char_end"))


def cmd_ask(args: argparse.Namespace) -> int:
    sr = Path(args.session_root).resolve()
    stores = _resolve_stores(args.stores)

    hits_by_store, timings = {}, {}
    for st in stores:
        hits, dt = _retrieve(sr, st, args.question, args.k, args.obsidian_source)
        hits_by_store[st] = hits
        timings[st] = round(dt * 1000)

    RRF_K = 60
    merged: dict[tuple, dict] = {}
    for st, hits in hits_by_store.items():
        for rank, h in enumerate(hits):
            m = merged.setdefault(_key(h.locator), {"hit": h, "stores": set(), "scores": {}, "rrf": 0.0})
            m["stores"].add(st)
            m["scores"][st] = h.score
            m["rrf"] += 1.0 / (RRF_K + rank)
    ordered = sorted(merged.values(), key=lambda m: -m["rrf"])
    top = ordered[: args.k]

    citations = []
    for m in top:
        citations.append({
            **citation_base(m["hit"].locator),
            "text": m["hit"].text,
            "found_by": sorted(m["stores"]),
            "scores": m["scores"],
            "rrf": round(m["rrf"], 4),
        })

    record = {
        "question": args.question,
        "stores": stores,
        "k": args.k,
        "generated_at": datetime.now(UTC).isoformat(),
        "retrieval_ms": timings,
        "citations": citations,
    }
    out_dir = paths.compare_dir(sr)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = record["generated_at"].replace(":", "").replace("-", "")
    (out_dir / f"ask-{stamp}.json").write_text(json.dumps(record, indent=2, ensure_ascii=False), "utf-8")

    if args.json:
        print(json.dumps(record, indent=2, ensure_ascii=False))
        return 0

    rt = " · ".join(f"{s} {timings[s]}ms" for s in stores)
    print(f"\n=== retrieved ({'+'.join(stores)}) · {rt} ===")
    print("Synthesize the answer from these passages and cite their locators:")
    for c in citations:
        print(f"  - {format_citation(c)}  found_by={'+'.join(c['found_by'])}\n      {snippet(c.get('text'))}")
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    a = sub.add_parser("ask", help="retrieve from the configured store(s) with sources (rag-query)")
    a.add_argument("question")
    a.add_argument("--stores", default="", help="obsidian | llama | both (default: $KSTORE_QUERY_STORES or both)")
    a.add_argument("--k", type=int, default=8)
    a.add_argument("--obsidian-source", default="raw", choices=["raw", "vault"],
                   help="keyword corpus for the obsidian arm (raw=source-of-truth, vault=synthesized pages)")
    a.add_argument("--session-root", default=paths.DEFAULT_SESSION_ROOT)
    a.add_argument("--json", action="store_true")
    a.set_defaults(func=cmd_ask)
