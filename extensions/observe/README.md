# observe

Network observability, the **read** grant. Fills the `forwarder` slot: every
endpoint's forwarder becomes a netgate (the `gate` library) that records each
connection, and a collector with no network writes the records to
`~/.glove/observe/<id>/net/`. With `transcripts: true` (default) the harness's
transcripts are exported to `~/.glove/observe/<id>/transcripts/`.

```yaml
extensions:
  observe:
    record: metadata          # metadata | full (cleartext method + URL; loud warning)
    record_headers: false     # record: full only; credentials redacted
    resolve: in-tunnel        # in-tunnel | none
    # resolver: dns://…:53    # default: the egress provider's (gluetun DNS, Tor SOCKS)
    exit_identity: auto       # auto | none | an https:// URL you name (see below)
    transcripts: true
    rotate_mb: 64
    keep: 8
    retain: none              # e.g. 12h
    skip: []                  # endpoint names that stay plain socat
```

Exit identity (`net/exit.ndjson`, written on the first answer and on change)
asks the egress's own software, never a lookup service glove picks. `auto`
follows the egress provider's `exit_identity` export:

| egress | source | what it is |
|---|---|---|
| `vpn` | `vpn-endpoint` | the VPN server's address, which gluetun's start script reads from its kill switch every 30 s (a reconnect to another server shows as a change; no lookup). The tunnel's entry address; see [vpn's "Exit identity"](../vpn/README.md#exit-identity-no-lookup-by-default) for what its health means |
| `vpn` with `publicip_api` | `gluetun:publicip` | gluetun's own lookup through the tunnel, with the service the operator named; emptied when the tunnel drops |
| `tor` | `via-proxy:check.torproject.org` | the Tor Project's check, every 5 minutes; `IsTor` must be true. Tor builds this gate its own circuit, so its exit need not be the agent's |
| `direct`, `corporate` | none | the exit is the host's (or the corporate proxy's) address |

One gate polls the exit, so no two write its records: the harness's own hop to
the egress proxy if it has one (Claude Code's `proxy`), otherwise the first
egress consumer's (`searxng-egress`, `webfetch-egress`, …); with none (or
that one in `skip`), there is no record and session.json says `none`.

vpn's address arrives in a file in gluetun's `exit` volume, which vpn `shares`
read-only with that polling gate (never with the harness); it has no
country or city. An absent file is "not known yet": no record until it appears.
An `https://` URL makes the gate poll that service through the egress instead
(geo if it answers ipinfo/echoip-style JSON); `none` records nothing.

Egress consumers get their own gate too: SearXNG leaves the egress network and
reaches the proxy only through `searxng-egress`.

Observe alone **never** reads rules: no gate mounts `~/.glove/control/`, none
gets `--rules`, and glove does not create `control/<id>/`
(`tests/test_observe_filter_split.py`). Add `filter: {}` for that.

CLI: `glove observe status [--json]`, `glove observe flows [--follow] [--json]
[--tail N]`. Live test: `tests/integration/test_observe.sh [direct|tor]`
(`RT=podman` too). Grant-state and hop fixtures for Layman
(`llm-auth`, `github`, `ssh`, `downloads`, …): `tests/fixtures/netobs-v3/`
(`fixtures/generate.py`; the scenarios are listed in its docstring).
