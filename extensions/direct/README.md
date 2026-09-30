# direct

Fills the `egress` slot with no tunnel: a tinyproxy sidecar is the only
container on the session's `wan` network, and egress consumers (`search`,
`webfetch`) reach the internet through it. Flows are labelled `route: direct`.
Use it when you want web tools but not anonymity. Choose `vpn` or `tor` for
that; only one egress provider can be active.

```yaml
extensions:
  direct: {}
```

Verify: before the harness starts, glove fetches `check_url` (default
`https://am.i.mullvad.net/ip`) through the proxy from a throwaway container on
the egress network; the session does not start if that fails.

tinyproxy runs with the full sidecar hardening (your uid, no capabilities,
read-only rootfs). It refuses local names, single-label names (other
containers) and non-public IP literals, CONNECT included, and allows CONNECT
only to ports 443 and 80. So the proxy is never a way into this machine or its
LAN. Names are judged by shape and never resolved: a public name that resolves
privately is not caught. See docs/SECURITY.md "Egress".
