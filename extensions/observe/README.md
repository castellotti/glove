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
    exit_identity: none       # via-proxy: poll the exit IP through the tunnel
    transcripts: true
    rotate_mb: 64
    keep: 8
    retain: none              # e.g. 12h
    skip: []                  # endpoint names that stay plain socat
```

Egress consumers get their own gate too: SearXNG leaves the egress network and
reaches the proxy only through `searxng-egress`.

Observe alone **never** reads rules: no gate mounts `~/.glove/control/`, none
gets `--rules`, and glove does not create `control/<id>/`
(`tests/test_observe_filter_split.py`). Add `filter: {}` for that.

CLI: `glove observe status [--json]`, `glove observe flows [--follow] [--json]
[--tail N]`. Live test: `tests/integration/test_observe.sh [direct|tor]`
(`RT=podman` too). Grant-state fixtures for Layman:
`tests/fixtures/netobs-v3/` (`fixtures/generate.py`).
