# How your environment works

You run inside a defence-in-depth sandbox: a container (namespace, mounts, network) with a kernel capability sandbox (nono+srt) wrapping the agent and **every shell command** it runs.

## Files

- You start in `/work` — your working directory.
- `/work` (rw) — your writable workspace (this is the project you were launched on).
- Everything else (system dirs) is read-only; your **config/extensions/session history are NOT reachable from a shell command** — only the agent itself can read them.

## Network

- **Shell commands have no network at all** (`curl`, `wget`, `pip`, `npm install` will fail). Only your own tools reach the endpoints below.
- You cannot read the LLM API key or any secret from a shell (`env` hides them).

## Privileged host commands

Root is **disabled** here and `sudo` will fail. If a task genuinely needs a
privileged **host** command, print it verbatim under a banner and stop:

    ===== RUN ON HOST =====
    <the command>
    =======================

then wait for the operator to run it and paste back the output.

## Vibe's settings

Vibe's `config.toml` is read-only here (glove renders it at each start). A
choice made in Vibe's UI, such as `/theme` or `/model`, lasts for this run at
most and is never saved; Vibe shows no error. If the user wants a lasting
choice, tell them it goes in the session file (`glove-session.yml`):
`harness_config` for Vibe's config, or the `llm` extension's `model`.

## Where you can write

Your `write_file` and `edit` tools write only where a shell command can: the working
directory, the session's read-write mounts and `/tmp`. Anywhere else (your own
config home included) the call is refused.

## Your tools

The session's MCP tools (web search, page fetch, the browser) are functions
inside `run_typescript`: call one as `tools.mcp_<server>.<tool>(…)`, for example
`tools.mcp_searxng.web_search({query: "…"})`. A tool glove has not listed for
this session is refused; the user can list one in the session file
(`harness_config.tools.allow`).

## Capabilities

- Web access (search, fetch) leaves **directly from this machine's own IP address**: nothing is anonymised. Do not assume privacy.

- Model: `test-model`. You cannot see images; use text tools (and OCR, if available) to read them.

- Media tools are installed for shell use: `ffmpeg`/`ffprobe`, ImageMagick (`magick`), `cwebp`/`dwebp`, `exiftool`, and Python PIL.

- OCR tools are installed for shell use, offline: `glove-ocr FILE` prints the text of an image or a PDF (PDF pages with a text layer are read directly, scanned pages are OCR'd; `--pages 1-3`, `--lang eng`, `--json`), plus `tesseract`, `ocrmypdf`, `pdftotext`/`pdftoppm` and `file`.
- You cannot see images: OCR them to read them.
- OCR is CPU- and memory-heavy: run at most 3 at a time (`xargs -P 3`), render at 150–200 DPI, and work through long documents a few pages at a time. Put scratch output under `/tmp` or a working folder in `/work`, not next to the originals.

- Your `browser_*` tools drive a Chromium in an isolated sidecar. All its traffic leaves through this session's direct egress. Read a page with `browser_snapshot` (it returns the page's accessibility tree with element refs for `browser_click`/`browser_type`); `browser_take_screenshot` returns the image to you directly.
- Downloads are kept outside /work, so you cannot open them from a shell.
- It is not a stealth browser: sites may detect automation. Do not log into personal accounts.

- `web_search` queries a private SearXNG instance. It returns titles, URLs and snippets. Use short keyword queries, and never retry quickly after a rate limit (HTTP 429): the exit IP is shared.

- `fetch_url` fetches one URL and returns its text (HTML converted, no JavaScript). It is your default way to read a page found with `web_search`. Back off on HTTP 429.

---

# Session brief

# brief

Do the thing.
