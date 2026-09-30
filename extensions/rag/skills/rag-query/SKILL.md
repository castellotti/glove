---
name: rag-query
description: "Answer a question from the operator's parsed documents (the knowledge stores) and return sources for verification. Use this for ANY question about the operator's data, files, or documents — retrieve, do not answer from general knowledge. Retrieves from the Obsidian store, the vector index, or both (configurable). Triggers: what does, find, search the documents, according to the files, look up, where does it say, cite, question about the data, summarize the documents, is there anything about."
---

# Answer from the knowledge stores, with sources

For any question about the operator's documents, answer **from the stores**, not
from general knowledge. First retrieve the relevant passages:

```sh
kstore ask "<the operator's question>"
```

`ask` retrieves from the configured store(s) (the `query_stores` setting, default
`both` = keyword/Obsidian + vector/llama, fused by rank) and prints the top
passages, each with the **original** file, page, and char/line locator and which
store found it. It does **not** write the answer — that's your job:

- **You synthesize the answer** from those passages (kstore has no LLM; you are
  the model). Ground every statement in the retrieved passages.
- **Always cite** each fact's locator (file, page, char/line) so the operator can
  open the original and verify. Quote when precise wording matters.
- If a passage looks truncated or you need more, re-run with `--k 12` or read the
  cited range from `/work/data/store/corpus/<doc>/<doc>.txt`.
- If `ask` returns no passages, the stores are probably empty — tell the operator
  to parse first (`/skill:rag-parse`), or offer to run it.

## Options

- `--stores obsidian|llama|both` — override the default backend for one query.
- `--k N` — retrieve more/less context (default 8).
For an explicit side-by-side comparison of keyword vs vector retrieval on the
same question (each store's latency + which passages it returned), use
`kstore compare "<question>"`, then explain the difference.
