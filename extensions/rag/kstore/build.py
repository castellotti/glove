"""`kstore build` / `kstore query` — llama_index on-disk RAG store."""

from __future__ import annotations

import argparse
import contextlib
import json
import sys
import time
from pathlib import Path

from . import paths, rag
from .locator import citation_base, format_citation, snippet


def _persist_dir(session_root: Path, corpus: str) -> Path:
    return paths.llama_dir(session_root) / corpus


def build_index(session_root: Path, corpus: str) -> int:
    import faiss
    from llama_index.core import Settings, StorageContext, VectorStoreIndex
    from llama_index.vector_stores.faiss import FaissVectorStore

    persist_dir = _persist_dir(session_root, corpus)
    persist_dir.mkdir(parents=True, exist_ok=True)

    Settings.embed_model = rag.make_embed()
    dim = len(Settings.embed_model.get_text_embedding("dimension probe"))

    if corpus == "raw":
        extracted = paths.corpus_dir(session_root)
        if not any(extracted.rglob("*.chunks.jsonl")):
            print(f"kstore build: no corpus at {extracted} — run `kstore extract` first", flush=True)
            return 2
        nodes = list(rag.iter_corpus_nodes(extracted))
        sources = rag.corpus_sources(extracted)
    elif corpus == "vault":
        from llama_index.readers.obsidian import ObsidianReader

        vault = paths.vault_dir(session_root)
        docs = ObsidianReader(str(vault)).load_data()
        from llama_index.core.node_parser import SentenceSplitter

        nodes = SentenceSplitter(chunk_size=800, chunk_overlap=100).get_nodes_from_documents(docs)
        sources = [{"source_path": "data/store/vault", "sha256": ""}]
    else:
        print(f"kstore build: unknown corpus '{corpus}'", flush=True)
        return 2

    if not nodes:
        print("kstore build: no nodes to index", flush=True)
        return 2

    faiss_index = faiss.IndexFlatIP(dim)
    vs = FaissVectorStore(faiss_index=faiss_index)
    storage = StorageContext.from_defaults(vector_store=vs)

    t0 = time.time()
    index = VectorStoreIndex(nodes, storage_context=storage, show_progress=True)
    index.storage_context.persist(persist_dir=str(persist_dir))
    rag.write_manifest(persist_dir, corpus=corpus, dim=dim, chunk_count=len(nodes), sources=sources)

    print(
        f"kstore build: indexed {len(nodes)} node(s) dim={dim} "
        f"from '{corpus}' in {time.time() - t0:.1f}s → {persist_dir}"
    )
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    return build_index(Path(args.session_root).resolve(), args.corpus)


def load_index(session_root: Path, corpus: str):
    from llama_index.core import Settings, StorageContext, load_index_from_storage
    from llama_index.vector_stores.faiss import FaissVectorStore

    persist_dir = _persist_dir(session_root, corpus)
    manifest = rag.read_manifest(persist_dir)
    rag.assert_embed_matches(manifest)
    Settings.embed_model = rag.make_embed()
    # llama_index announces the MockLLM on stdout, which would corrupt `--json`
    with contextlib.redirect_stdout(sys.stderr):
        Settings.llm = None
    vs = FaissVectorStore.from_persist_dir(str(persist_dir))
    storage = StorageContext.from_defaults(vector_store=vs, persist_dir=str(persist_dir))
    return load_index_from_storage(storage)


def run_query(session_root: Path, corpus: str, question: str, k: int) -> dict:
    t0 = time.time()
    index = load_index(session_root, corpus)
    t_load = time.time() - t0

    t1 = time.time()
    nodes = index.as_retriever(similarity_top_k=k).retrieve(question)
    t_query = time.time() - t1

    citations = []
    for sn in nodes:
        md = sn.node.metadata or {}
        citations.append({
            **citation_base(md),
            "text": sn.node.get_content(),
            "score": round(float(sn.score), 4) if sn.score is not None else None,
        })
    return {
        "store": f"llama:{corpus}",
        "question": question,
        "k": k,
        "citations": citations,
        "load_ms": round(t_load * 1000),
        "query_ms": round(t_query * 1000),
    }


def _print_result(res: dict) -> None:
    print(f"\n=== {res['store']} · load {res['load_ms']}ms · retrieve {res['query_ms']}ms ===")
    print("top passages (synthesize your answer from these, cite the locators):")
    for c in res["citations"]:
        print(f"  - {format_citation(c)}  (score {c['score']})\n      {snippet(c.get('text'))}")


def cmd_query(args: argparse.Namespace) -> int:
    session_root = Path(args.session_root).resolve()
    res = run_query(session_root, args.corpus, args.question, args.k)
    if args.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
    else:
        _print_result(res)
    return 0


def register(sub: argparse._SubParsersAction) -> None:
    b = sub.add_parser("build", help="build/persist the llama_index FAISS RAG store")
    b.add_argument("--corpus", default="raw", choices=["raw", "vault"])
    b.add_argument("--session-root", default=paths.DEFAULT_SESSION_ROOT)
    b.set_defaults(func=cmd_build)

    q = sub.add_parser("query", help="retrieve top-k passages from the vector store (no LLM)")
    q.add_argument("question")
    q.add_argument("--corpus", default="raw", choices=["raw", "vault"])
    q.add_argument("--k", type=int, default=8)
    q.add_argument("--session-root", default=paths.DEFAULT_SESSION_ROOT)
    q.add_argument("--json", action="store_true", help="emit a JSON record")
    q.set_defaults(func=cmd_query)
