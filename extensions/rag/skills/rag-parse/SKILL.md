---
name: rag-parse
description: "Process/ingest the documents in /work/data/input into the knowledge stores (Obsidian vault + vector RAG index). Incremental: only new or changed files are processed, and files removed from input are pruned from the stores. Use when the operator wants to load, process, parse, ingest, index, or update their data. Triggers: parse, parse the files, process the input, ingest, index the documents, update the store, re-parse, load my data, refresh the index."
---

# Parse input into the knowledge stores

Turn everything in `/work/data/input` into both knowledge stores with one
incremental, deterministic command. It extracts text + source locators, (re)builds
the vector index, and writes Obsidian source-pages — skipping unchanged files and
pruning ones the operator removed. It reads PDFs (OCR'ing scanned ones), text and
Markdown files, and images (OCR'd with tesseract).

```sh
kstore sync
```

Then:

- Report the summary line it prints (new / changed / unchanged / removed, OCR'd,
  vault pages).
- If it lists files as **needs OCR** (scanned PDFs, and `ocrmypdf` was not
  available), OCR each into the cache and re-run, e.g.:
  `ocrmypdf --skip-text "/work/data/input/FILE.pdf" /work/data/store/cache/FILE-ocr.pdf`
  then `kstore sync`. (In this sandbox `ocrmypdf` is installed, so
  `sync` normally OCRs scanned PDFs automatically.)
- **Never** write extracted text, OCR output, or page images to
  `/work/data/output`. That directory is for final deliverables only. All derived
  and transient artifacts belong under `/work/data/store` (the tools handle this).

## Optional: richer Obsidian synthesis

`sync` populates the vault with one source-page per document (fast, mechanical).
For a cross-linked knowledge graph with claim ledgers and Maps of Content, the
operator can additionally ask for synthesis — run `/skill:wiki-ingest` on
specific documents. That is a heavier, LLM-driven layer on top of the source
pages; only do it when asked, and a few documents at a time (it consumes context).
