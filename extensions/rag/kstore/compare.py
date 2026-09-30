"""`kstore compare` — side-by-side RAG vs keyword retrieval."""

from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path

from . import paths
from .bm25 import BM25, Hit
from .corpus import load_records
from .locator import citation_base, format_citation


def hit_to_citation(h: Hit) -> dict:
    return {**citation_base(h.locator), "text": h.text, "score": h.score}


def retrieve_bm25(session_root: Path, source: str, question: str, k: int) -> tuple[list[Hit], float]:
    records = load_records(source, session_root=session_root)
    t0 = time.time()
    hits = BM25(records).search(question, k=k)
    return hits, time.time() - t0


def retrieve_llama(session_root: Path, corpus: str, question: str, k: int) -> tuple[list[Hit], float]:
    from .build import load_index

    index = load_index(session_root, corpus)
    retriever = index.as_retriever(similarity_top_k=k)
    t0 = time.time()
    nodes = retriever.retrieve(question)
    dt = time.time() - t0
    hits = [
        Hit(
            text=n.node.get_content(),
            locator=dict(n.node.metadata or {}),
            score=round(float(n.score), 4) if n.score is not None else 0.0,
        )
        for n in nodes
    ]
    return hits, dt


def _run_store(session_root: Path, store: str, question: str, k: int, *,
               bm25_source: str, llama_corpus: str) -> dict:
    if store == "bm25":
        hits, r_dt = retrieve_bm25(session_root, bm25_source, question, k)
        label = f"bm25:{bm25_source}"
    elif store == "llama":
        hits, r_dt = retrieve_llama(session_root, llama_corpus, question, k)
        label = f"llama:{llama_corpus}"
    else:
        raise ValueError(f"unknown store: {store}")

    return {
        "store": label,
        "retrieval_ms": round(r_dt * 1000),
        "citations": [hit_to_citation(h) for h in hits],
    }


def _print_store(res: dict) -> None:
    print(f"\n=== {res['store']} · retrieval {res['retrieval_ms']}ms ===")
    for c in res["citations"]:
        print(f"  - {format_citation(c)}  (score {c['score']})")


def cmd_compare(args: argparse.Namespace) -> int:
    session_root = Path(args.session_root).resolve()
    stores = [s.strip() for s in args.stores.split(",") if s.strip()]
    results = []
    for store in stores:
        results.append(
            _run_store(
                session_root, store, args.question, args.k,
                bm25_source=args.bm25_source, llama_corpus=args.llama_corpus,
            )
        )

    record = {
        "question": args.question,
        "k": args.k,
        "generated_at": datetime.now(UTC).isoformat(),
        "stores": results,
    }
    out_dir = paths.compare_dir(session_root)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = record["generated_at"].replace(":", "").replace("-", "")
    out_path = out_dir / f"{stamp}.json"
    out_path.write_text(json.dumps(record, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.json:
        print(json.dumps(record, indent=2, ensure_ascii=False))
    else:
        for res in results:
            _print_store(res)
        print(f"\nrecord: {out_path}")
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    c = sub.add_parser("compare", help="compare RAG vs keyword/vault retrieval (speed + citations)")
    c.add_argument("question")
    c.add_argument("--k", type=int, default=8)
    c.add_argument("--stores", default="bm25,llama", help="comma list: bm25,llama")
    c.add_argument("--bm25-source", default="raw", choices=["raw", "vault"])
    c.add_argument("--llama-corpus", default="raw", choices=["raw", "vault"])
    c.add_argument("--session-root", default=paths.DEFAULT_SESSION_ROOT)
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_compare)
