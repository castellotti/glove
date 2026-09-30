# pi-rag template

Private, **offline** document Q&A with Pi. Drop documents (PDFs, scans, text,
images) into `work/data/input/`; Pi parses them into two source-traceable
stores (a keyword/Obsidian vault and a FAISS vector index, via the `rag`
extension's kstore) and answers questions from them with citations: file,
page and char/line. There is no egress provider: the sandbox reaches only
your model, and shell commands have no network at all. Embeddings run
in-process from a model on disk.

```sh
glove new pi-rag ~/work/papers && cd ~/work/papers
$EDITOR glove-session.yml        # llm settings + rag.models_dir (every <set-me>)
glove rag fetch-model            # once: downloads the embedding model into models_dir (needs internet)
glove keychain set <service>     # if you referenced keychain:<service>
mkdir -p work/data/input && cp ~/Documents/*.pdf work/data/input/
glove check && glove up
```

Then ask Pi to *"parse the documents"* and *"what does the report say about X,
with sources?"*. Final deliverables go to `work/data/output/`; everything
derived (corpus, stores, OCR cache) lives in `work/data/store/` and can be
rebuilt.

A vision-capable model helps with scans and figures. Set `rag.obsidian_dir` to
a claude-obsidian checkout for its vault-synthesis skills (`wiki-ingest`, …).
When Pi can't parse a file it writes `work/reports/<file>.md` naming the
missing package: add it to `apt_packages:`/`pip_packages:` in the session file
and relaunch.
