# tor

Fills the `egress` slot with Tor. Two sidecars, both built from pinned Alpine:
`tor` (the only container on the session's `wan` network; SOCKS on a private
`torlink` network and on the internal egress network, where observe's gates use
it to resolve names in-tunnel) and `privoxy`, the HTTP proxy egress consumers
use on the internal egress network. privoxy forwards every request to Tor by hostname, so
names are resolved at the Tor exit. Flows are labelled `route: tor`.

```yaml
extensions:
  tor: {}
  # tor: { exit_nodes: ["{se}", "{ch}"], strict_nodes: false, host_check_url: https://<your echo service> }
```

Verify: Tor's SOCKS port must open, then `exit-confirmed` (the `exitcheck`
library, through tor's `verify` hook): the Tor Project's
own check (`https://check.torproject.org/api/ip`), fetched through privoxy, must
answer `IsTor: true` with one valid IP. With `host_check_url` set (no default),
that service must also see a different IP from this machine than through Tor.
The first circuit can take a minute or two. Many sites block or CAPTCHA Tor
exits; the `search` extension picks engines that tolerate Tor.

Exit identity: observe's `exit_identity: auto` (its default) polls the same
check through one gate every 5 minutes (see observe's README). Tor isolates circuits
per client, so the exit it records is the gate's own, not necessarily the
agent's.
