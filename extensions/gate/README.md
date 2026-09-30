# gate (library)

The netgate: glove's instrumented forwarder and telemetry collector, as one
stdlib-only Python image (`netgate/`, built from a pinned `python:3.12-alpine`).
Not selectable: `observe` and `corporate` require it and it is added
automatically.

- `python -m netgate forward` — a drop-in for a socat forwarder (`tcp` mode), or
  an HTTP proxy that records each destination and chains to an upstream proxy
  by hostname (`http-proxy` mode), with the built-in SSRF guard, optional
  in-tunnel resolution, `rules.json` enforcement (`--rules`, only with the
  filter grant) and exit-identity polling.
- `python -m netgate forward --mode http-proxy --upstream direct` — the
  `corporate` egress: resolves and dials destinations itself under a static
  default-block allowlist; never reads `rules.json`.
- `python -m netgate collect` — the single writer of `net/`, `network_mode: none`.

`gatelib.py` is the host side (endpoint → gate spec → command line), used by the
`observe` hook. Record schemas are v1 and frozen (the Layman handoff);
`tests/` pins them, the no-host-DNS invariant, and the direct mode.
