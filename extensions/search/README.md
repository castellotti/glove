# search

Gives the agent a `web_search` tool backed by a per-session
[SearXNG](https://docs.searxng.org/). Pi loads a native extension that queries
SearXNG through the `search` endpoint (`glove-<id>-search:8080`). Harnesses that
speak MCP (Vibe, Claude Code) get the `searxng` MCP server instead, served over
streamable HTTP by the `searxng-mcp` sidecar and reached through the
`search-mcp` endpoint (`glove-<id>-search-mcp:8000/mcp`), so the harness never
reaches SearXNG itself and nothing is baked into its image. The sidecar
(`image/`: python slim + `mcp`, installed from a hash-pinned `requirements.txt`)
sits only on `searchnet`, answers only requests naming its forwarder as Host,
and talks to SearXNG and nothing else. Shell commands still have no network.

Requires an egress provider (`vpn`, `tor`, `direct` or `corporate`):

```yaml
extensions:
  tor: {}
  search: {}
  # search: { groups: { security_mode: false }, engines: { google: enable, qwant: disable } }
```

Sidecars: `searxng` (on the internal egress network plus a private `searchnet`)
and `valkey` (on `searchnet` only, nothing persisted). Every engine request
SearXNG makes goes through the egress provider's proxy. The egress network is
internal, so if that proxy is down SearXNG has no route out; it does not fall
back to a direct connection. With `observe`, SearXNG leaves the egress network
altogether: its requests go through its own gate (the `searxng-egress`
endpoint, `client: searxng`) on `searchnet`, which is then its only route to the
proxy, and every engine it contacts shows up in the flow record.

Settings are rendered into `.glove/ext/search/searxng/settings.yml` at
`glove plan`/`glove up`: the base follows the egress route (Tor-tolerant engines
and longer timeouts for `tor`), then engine groups and overrides apply:

| group | removes engines that… |
|---|---|
| `blocks_tor` | block or CAPTCHA Tor exits |
| `requires_license` | need a paid/registered API key |
| `phones_home` | contact a third party at startup |
| `security_mode` | come from data-harvesting platforms |

All groups are on by default. `engines: {name: enable|disable}` wins over
groups. The SearXNG secret key is generated once per session
(`.glove/ext/search/secret_key`, 0600).

Verify: SearXNG's `/healthz` must answer before the harness starts.
