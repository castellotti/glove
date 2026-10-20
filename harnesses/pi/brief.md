## Pi's settings

Pi's settings files are read-only here (glove renders them at each start). A
choice made in Pi's UI, such as `/model` or `/settings`, lasts for this run at
most and is never saved, even when Pi reports it as saved. If the user wants a
lasting choice, tell them it goes in the session file (`glove-session.yml`):
`harness_config` for Pi's settings, or the `llm` extension's `model`.

## Where you can write

Your `write` and `edit` tools write only where a shell command can: the working
directory, the session's read-write mounts and `/tmp`. Anywhere else (your own
config home included) the call is refused.

## Your tools

The session's MCP tools (web search, page fetch, downloads, the browser) are
named `mcp__<server>__<tool>`, for example `mcp__searxng__web_search` and
`mcp__webfetch__fetch_url`; the session's notes may name them by their short
form (`web_search`, `fetch_url`). Only the MCP servers glove renders load (a
project's `.pi/mcp.json` does not), and a tool glove has not listed for this
session is refused.
