# ocr

Bakes an offline OCR toolchain into the harness image: tesseract (with the
language packs you choose), ocrmypdf, poppler (`pdftotext`, `pdftoppm`,
`pdfinfo`), ghostscript and `file`, plus a small `glove-ocr` command. The tools
run as ordinary shell commands under the ring-1 tool policy (confined to
`/work`, rw mounts and `/tmp`, no network). No sidecars, no network.

```yaml
extensions:
  ocr: {}                        # English
  # ocr: { languages: [eng, deu] }
```

| Setting | Meaning |
|---|---|
| `languages` | tesseract language packs, as Debian package suffixes (`eng`, `deu`, `chi-sim`, …). Default `[eng]`. |

## `glove-ocr`

```sh
glove-ocr scan.png                    # the image's text
glove-ocr report.pdf                  # every page: text layer where there is one, OCR where not
glove-ocr report.pdf --pages 2-4 --force-ocr --lang eng+deu --json
```

A PDF prints one `=== page N (text|ocr) ===` block per page; `--json` prints
`[{page, method, text}]`. `--dpi` sets the render resolution for OCR'd pages
(default 200).

## Vision

There is no `--vision` mode. A shell command has no network, so it cannot call
the session's model, and llama_index's `image_vision_llm` reader runs a local
BLIP-2 model (torch + transformers, several GB) rather than the llm endpoint.
When the model has vision (the `llm` extension's `capabilities.vision`), the
agent looks at images itself; the brief tells it which applies.
