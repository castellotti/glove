# search

Gives the agent a `web_search` tool backed by SearXNG. Pi loads a native
extension; Vibe gets a stdio MCP server. Both reach SearXNG only through the
`search` endpoint (`glove-<id>-search:8080`), and shell commands still have no
network.

**Interim (v3 M2):** SearXNG runs outside the session, on this Mac, and the
setting names its port. M4 moves SearXNG and valkey into the session behind the
`egress` slot.

```yaml
extensions:
  search: { host_port: 8888 }
```
