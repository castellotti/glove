# tor

Fills the `egress` slot with Tor. Two sidecars, both built from pinned Alpine:
`tor` (the only container on the session's `wan` network; SOCKS on a private
`torlink` network) and `privoxy`, the HTTP proxy egress consumers use on the
internal egress network. privoxy forwards every request to Tor by hostname, so
names are resolved at the Tor exit. Flows are labelled `route: tor`.

```yaml
extensions:
  tor: {}
  # tor: { exit_nodes: ["{se}", "{ch}"], strict_nodes: false }
```

Verify: Tor's SOCKS port must open, then `exit-ip-differs` (the IP an echo
service sees through privoxy must differ from this machine's). The first
circuit can take a minute or two. Many sites block or CAPTCHA Tor exits; the
`search` extension picks engines that tolerate Tor.
