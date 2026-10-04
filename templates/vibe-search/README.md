# vibe-search template

Private web research with Mistral Vibe: the `pi-search` template with Vibe as
the harness. `searxng_web_search` (a per-session SearXNG) and
`webfetch_fetch_url` reach Vibe as MCP tools served by hardened sidecars, and
both leave only through the session's egress provider, a VPN tunnel by default
(Tor or direct are one line away).

```sh
glove new vibe-search ~/work/research-1 && cd ~/work/research-1
$EDITOR glove-session.yml        # llm + vpn settings (every <set-me>)
glove keychain set <service>     # for each keychain:<service> you referenced
glove check && glove up
```

The model must speak an OpenAI-style API (Vibe has no Anthropic backend).
`harness_config` is passed through to Vibe's `config.toml`. OCR (`glove-ocr`)
and the media tools run offline in the shell, like every tool.
