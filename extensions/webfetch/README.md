# webfetch

Reads one URL as text through the session's egress proxy (HTML converted,
bodies capped at 5 MB, output at `max_chars`). Requires an egress provider
(`vpn`, `tor`, `direct` or `corporate`):

```yaml
extensions:
  vpn: { … }
  webfetch: {}
```

**Pi** gets a `web_fetch` tool (`pi-extension/`). The harness reaches the
egress proxy only through the `proxy` endpoint (`glove-<id>-proxy:8888`), set
as `GLOVE_FETCH_PROXY`. The Pi extension attaches it per request with undici's
`ProxyAgent`, never as a global dispatcher, so the harness's LLM traffic never
goes through it. An `http://` URL goes to the proxy as a plain absolute-form
request, as a browser sends it; only `https://` is tunnelled with CONNECT
(`proxyTunnel: false`; the fetcher's urllib does the same). The extension and
its npm dependencies (pinned) are baked into the session image at build time;
nothing is installed into the harness home. `GLOVE_FETCH_PROXY` (and the
other variables Pi's extension reads) is set for the harness process only: the
tool wrapper unsets it before every shell command, which has no network to
use it on (`env: {…, shell: false}` in the manifest).

**Claude Code** keeps its own `WebFetch`: glove allows it and sets
`HTTPS_PROXY`/`HTTP_PROXY` to the `proxy` endpoint in the read-only managed
settings, with every session forwarder (the inference link, MCP servers) and
loopback in `NO_PROXY`. Its destinations are policed at the egress, not in the
client: tinyproxy's filter (`direct`), the tunnel (`tor`, `vpn`), the corporate
gate, or with `observe` the gate's SSRF guard. It also keeps Claude Code's own
behaviour: a domain preflight to `api.anthropic.com` (through the inference
link with `provider: anthropic`, otherwise through the egress) and a small-model
summary of each page. See `docs/SECURITY.md` for what this widens.

**Vibe** gets a `fetch_url` tool from the `webfetch` MCP server,
served over streamable HTTP by the `fetcher` sidecar (`image/webfetch_mcp.py`,
a port of the Pi extension and its guard; python slim + `mcp` from a
hash-pinned `requirements.txt`). The harness reaches it through the
`webfetch-mcp` endpoint (`glove-<id>-webfetch-mcp:8000/mcp`) and never sees the
egress proxy. The fetcher sits on a private `fetchnet` and answers only
requests naming its forwarder as Host. It reaches the proxy directly on the
egress network, or with `observe` only through its own gate (`webfetch-egress`,
flows `client: webfetch`).

**Destinations.** Both tools read public web pages only. It refuses
non-global IP literals (loopback, RFC 1918, link-local/metadata, CGNAT, ULA …),
single-label and local names (`localhost`, `*.local`, `*.internal`,
`host.docker.internal` …) and URLs with credentials, before anything is sent.
Vibe's guard also refuses IPv4 addresses spelled any way but as a dotted quad
(`0xa.0.0.1`, `012.0.0.1`, `127.1`), which the resolver behind the proxy would
read as addresses (Node's URL rewrites them before Pi's guard sees them), and
judges IPv6 in its compressed form. It
follows redirects itself (at most 5) and checks every hop. Names are judged by
shape and never resolved, so a public name that resolves to a private address is
not caught here. Under `direct`, tinyproxy's filter is the second layer with the
same limit. Tor exits and gluetun's kill switch refuse private destinations.

Under `corporate`, the operator's allowlist (`GLOVE_FETCH_ALLOW`, from the
session file) is let through even when private; this machine, link-local/metadata
and multicast stay refused whatever it says, and the corporate gate enforces the
same list.

**Refusals by policy.** When the egress gate refuses a request (a `filter` rule,
the corporate allowlist, the SSRF guard), the tool asks the proxy once for
the reason and tells the agent it was refused by the session's network policy,
not that the network failed, so it does not retry or look for a way around.

**Binary bodies and rate limits.** Both tools return text only. A response
whose content type isn't text (`text/*`, JSON, XML, JavaScript), or an
unlabelled or text one with a NUL byte in its first 4 KB, is described instead
(`[binary: application/pdf, 812345 bytes] <url>`) and the rest of its body is
never read. The note then points to `web_download` when the session has it,
otherwise it tells the agent to ask the operator for the file. A 429 says how
long the server asked to wait (`Retry-After`, in seconds or as a date).
`pi-extension/body.ts` and the fetcher share these rules; a test runs both
on the same cases.

## Downloads (`downloads: work`, off by default)

```yaml
  webfetch: { downloads: work, min_free: 5g }
```

Adds `web_download` and `web_download_status` for every harness: Pi
registers them from the `fetcher` sidecar's MCP (`GLOVE_DOWNLOAD_MCP_URL`),
Vibe and Claude Code get the `webdownload` MCP server. The fetcher runs for
any harness with downloads on, and saves files to `<session>/downloads/`; the
harness sees that directory **read-only** at `/work/downloads/` (a core
`outputs:` directory), so the agent extracts or converts into a folder of its
own. Under `observe` the hops are labelled `tool: web_download`, apart from
`web_fetch`, so a `filter` rule can tell them apart.

| Risk | How it is met |
|---|---|
| Writing through a planted symlink into the harness home | The sidecar writes, never the harness process. Its only writable bind is `<session>/downloads/`, outside `/work`, so the agent cannot swap it for a link (a runtime re-resolves a bind source at every restart). Files open `O_EXCL\|O_NOFOLLOW` as `<name>.part`, linked to a free name only when complete; never an overwrite. |
| Filling the host disk | `min_free` (default `2g`): a download must leave that much free on the host volume, checked against `Content-Length` before it starts and while it runs. A reserve, not a size cap. |
| Memory | Streamed to disk in chunks, hashed on the way. |
| Long tool calls | Jobs are asynchronous: `web_download` waits at most `wait_s` (≤ 45 s), then returns a job id; `web_download_status` (or `ls -la /work/downloads`) shows progress. 120 s idle timeout, no total limit. At most 3 at once. |
| A failed transfer | The `.part` is kept; calling `web_download` again with the URL resumes it (`Range`/`If-Range`; a server that answers 200 or 416 starts over). |
| A non-public destination | The same guard as `web_fetch`, on every redirect hop, then the egress layer. |
| Integrity | The result has size, sha256, final URL and content type, to check against a published checksum. |
| Hostile content | Files are untrusted (the brief says so). Files written through a bind carry no macOS quarantine attribute: be careful opening one from Finder. |
