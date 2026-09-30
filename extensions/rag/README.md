# rag

Offline, source-traceable document Q&A. Bakes **kstore** into the harness
image: it turns `/work/data/input` into two stores and retrieves from them with
citations back to the original file, page and char/line range:

- a **keyword** store: an Obsidian-compatible vault of source pages, searched
  with BM25;
- a **vector** store: a FAISS index built with llama_index and fastembed
  embeddings computed in-process (no network, no model server).

kstore never calls a model; the agent synthesizes answers from what it
retrieves. Requires the `ocr` extension (scanned PDFs and images are OCR'd).
No egress provider is needed, and none is used.

```yaml
extensions:
  ocr: {}
  rag:
    models_dir: ~/models/fastembed          # read-only in the session
    # embed_model: BAAI/bge-small-en-v1.5
    # query_stores: both                    # both | obsidian | llama
    # obsidian_dir: ~/src/claude-obsidian   # optional, read-only
```

| Setting | Meaning |
|---|---|
| `models_dir` | **required.** Host directory holding the fastembed model cache; mounted read-only at `/mnt/rag-models`. Fill it once with `glove rag fetch-model` (needs internet). |
| `embed_model` | fastembed model id (default `BAAI/bge-small-en-v1.5`). The index records it; a mismatch asks for a rebuild. |
| `query_stores` | default for `kstore ask`: `both` (fused by rank), `obsidian` or `llama`. |
| `obsidian_dir` | optional claude-obsidian checkout, mounted read-only at `/mnt/rag-obsidian`: Pi gets its offline skills (`wiki-ingest`, `wiki-lint`, `wiki-mode`, `obsidian-markdown`, `canvas`, `think`). |

```sh
glove rag fetch-model        # in the session dir: download embed_model into models_dir
```

## In the session

| Command | What |
|---|---|
| `kstore sync` | incremental: extract new/changed inputs (PDF, text/Markdown, images), OCR scans, prune removed files, rebuild both stores |
| `kstore ask "<question>"` | top passages from the stores, each with its locator and which store found it (`--k`, `--stores`, `--json`) |
| `kstore compare "<question>"` | keyword vs vector side by side: latency and citations |

Pi's skills `rag-parse` (`kstore sync`) and `rag-query` (`kstore ask`) wrap
them. Layout under `/work/data`: `input/` (the operator's files), `output/`
(deliverables only), `store/` (everything derived: corpus, vault, index, OCR
cache, comparison records).

Ported from the `glove-pi-rag` template's `tools/kstore`. Changes: environment
variables are `KSTORE_*` (were `PIRAG_*`), images are OCR'd, and a scanned
PDF's citations name the original input rather than the OCR'd copy in the
cache.
