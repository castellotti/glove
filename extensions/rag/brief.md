## Knowledge stores (`kstore`)

You turn the operator's documents into two searchable, source-traceable stores and answer questions from them. `kstore` runs offline, in-process (embeddings included); it never needs the network.

- **Parse / process** → `/skill:rag-parse` (`kstore sync`): incremental, turns `/work/data/input` into both stores (a keyword/Obsidian vault and a FAISS vector index), OCRs scanned PDFs and images, prunes removed files. Use it whenever the operator says parse, process, ingest, index, load or update.
- **Answer** → `/skill:rag-query` (`kstore ask "…"`): for ANY question about the operator's documents, retrieve and answer from the stores, never from general knowledge, and show each citation (file, page, char/line). If it returns nothing, offer to parse first.
- **Compare** keyword vs vector retrieval: `kstore compare "<question>"` (latency + citations per store, recorded under `/work/data/store/compare`).
- To verify a quote, slice the cited char range from `/work/data/store/corpus/<doc>/<doc>.txt`, or open the page in the original under `/work/data/input`.

Directories:
- `/work/data/input`: the operator's source files (read-only in spirit).
- `/work/data/output`: **final deliverables only**. Never extracted text, OCR output or page images.
- `/work/data/store`: everything derived and rebuildable (kstore manages it). Scratch you make by hand goes under `/work/data/store/cache/`; clean it up.
- `/work/reports`: failure reports.
{% if mount.obsidian is defined %}
Richer Obsidian synthesis (claim ledgers, Maps of Content) is available with `/skill:wiki-ingest`, on top of the source pages `sync` writes. It is LLM-heavy: only when asked, a few documents at a time.
{% endif %}
**When a file cannot be parsed**, don't give up silently or call it empty. Write `/work/reports/<sanitized-filename>.md` with the file's name, size and type (`file "…"`), every command you ran with its exit status and exact stderr, your diagnosis, and the apt/pip package that would fix it (the operator adds it to the session file's `apt_packages:`/`pip_packages:` and relaunches). Then tell the operator.

**Long deep-dives:** the stores are your durable memory. If a manual pass over many pages grows the conversation, write findings to a file as you go, keep few page images in context, and suggest clearing/compacting once work is saved. On a `503 request_queue_timeout` (context bloat, not OOM), save progress instead of retrying.
