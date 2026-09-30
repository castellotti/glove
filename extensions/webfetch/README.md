# webfetch

Gives Pi a `web_fetch` tool: fetch one URL through the session's egress proxy
and return readable text (HTML converted by `html-to-text`, bodies capped at
5 MB, output at `max_chars`). Requires an egress provider (`vpn`, `tor`,
`direct` or `corporate`).

```yaml
extensions:
  vpn: { … }
  webfetch: {}
```

The harness reaches the egress proxy only through the `proxy` endpoint
(`glove-<id>-proxy:8888`), set as `GLOVE_FETCH_PROXY`. The Pi extension attaches
it per request with undici's `ProxyAgent`, never as a global dispatcher, so
the harness's LLM traffic never goes through it. The extension and its npm
dependencies (pinned) are baked into the session image at build time; nothing
is installed into the harness home.

Pi only: with `harness: vibe` the session is refused.

**Destinations.** `web_fetch` reads public web pages only. It refuses
non-global IP literals (loopback, RFC 1918, link-local/metadata, CGNAT, ULA …),
single-label and local names (`localhost`, `*.local`, `*.internal`,
`host.docker.internal` …) and URLs with credentials, before anything is sent. It
follows redirects itself (at most 5) and checks every hop. Names are judged by
shape and never resolved, so a public name that resolves to a private address is
not caught here. Under `direct`, tinyproxy's filter is the second layer with the
same limit. Tor exits and gluetun's kill switch refuse private destinations.

Under `corporate`, the operator's allowlist (`GLOVE_FETCH_ALLOW`, from the
session file) is let through even when private; this machine, link-local/metadata
and multicast stay refused whatever it says, and the corporate gate enforces the
same list.

**Refusals by policy.** When the egress gate refuses a request (a `filter` rule,
the corporate allowlist, the SSRF guard), `web_fetch` asks the proxy once for
the reason and tells the agent it was refused by the session's network policy,
not that the network failed, so it does not retry or look for a way around.
