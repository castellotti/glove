# vpn

Fills the `egress` slot with a [gluetun](https://github.com/qdm12/gluetun) VPN
tunnel. gluetun is the only container on the session's `wan` network; its
kill-switch firewall drops anything that does not go through the tunnel, and
egress consumers (`search`, `webfetch`) reach the internet only through its
HTTP proxy on the internal egress network. Flows are labelled `route: vpn`.

```yaml
extensions:
  vpn:
    provider: <set-me>                     # a gluetun provider name, or custom
    wireguard_key: keychain:my-vpn-wg-key  # store it: glove keychain set my-vpn-wg-key
    addresses: 10.0.0.2/32                 # when the provider needs WIREGUARD_ADDRESSES
    countries: [Sweden]
```

| setting | meaning |
|---|---|
| `provider` | gluetun's `VPN_SERVICE_PROVIDER`, or `custom` (then `public_key` and `endpoint: ip:port`) |
| `type` | `wireguard` (default) or `openvpn` (`openvpn_user`/`openvpn_password` refs) |
| `wireguard_key` | Keychain/env reference to the WireGuard private key |
| `countries`, `cities`, `hostnames` | gluetun's server selection, for a named provider; `custom` has no server list, so they are refused there |
| `register_hook` | see below |
| `location` | with `register_hook`: where the hook picks its server, in the hook's own terms (e.g. the provider's region id); the hook gets it as `VPN_LOCATION` |
| `check_url` | a URL gluetun's proxy must fetch (`http-ok`; default `https://on.quad9.net`, no IP lookup) |
| `publicip_api` | turns gluetun's own exit lookup on, through the tunnel, with a service you name (gluetun's `PUBLICIP_API`, e.g. `echoip#https://<your server>`); no default |
| `host_check_url` | opt-in leak check: this service, asked from the host and through the tunnel, must see two different IPs; no default |
| `dns_upstream`, `health_targets`, `health_icmp` | gluetun's DNS upstream and health-check targets (default Quad9) |

Secrets are references (`keychain:<service>` or `env:<VAR>`), resolved in
memory at `glove up` and handed to gluetun as compose secrets
(`/run/glove-secrets/…`). They are never in a file, `docker inspect` or the
session directory.

## Register hook (fresh key per launch)

Some providers issue short-lived WireGuard keys through an account API. Put an
executable in the session's `local/` (never mounted into the harness) and
point `register_hook` at it:

```yaml
  vpn:
    provider: custom
    register_hook: local/register.sh
    register_user: keychain:my-vpn-user
    register_pass: keychain:my-vpn-pass
    location: <set-me>               # optional: the region id your hook knows
```

At every `glove up` glove runs it on this machine with the account username
and password on stdin (one per line) and `location`, if set, as `VPN_LOCATION`
in its environment (never one inherited from your shell). The hook chooses the
server, so this is how a session picks where it exits: gluetun's `countries`,
`cities` and `hostnames` filter a named provider's server list, and `custom`
has none (gluetun refuses to start with them, so glove refuses them first).
Check the id against your provider's own list: a region's id and name can
differ from the place you expect. The hook must print exactly these lines on
stdout (progress on stderr):

```
WIREGUARD_PRIVATE_KEY=…
WIREGUARD_PUBLIC_KEY=…
WIREGUARD_ENDPOINT_IP=…
WIREGUARD_ENDPOINT_PORT=…
WIREGUARD_ADDRESSES=…
```

The private key goes to gluetun as a compose secret. The other values go into
gluetun's environment for that `compose up` only. The hook path must resolve
inside `local/`, so a symlink into `work/` is refused.

## Verify

Before the harness starts: gluetun's healthcheck must report healthy (on
failure glove reads tun0's byte counter to tell a dead handshake from other
problems), then `egress-up`: gluetun's proxy must fetch `check_url`, then
`exit-confirmed` (the `exitcheck` library, through vpn's `verify` hook): the
exit file below must hold one valid IP. With
`host_check_url` set, that service must also see a different IP from this
machine than through the tunnel. Any failure stops the session's sidecars;
nothing starts half-tunnelled.

## Exit identity (no lookup by default)

gluetun's start script is wrapped: it publishes the session's exit as one bare
IP in `/run/glove-exit/ip`, in vpn's `exit` volume.

- **Default (`vpn-endpoint`):** the VPN server's endpoint, read every 30 s
  (every 2 s until known) from gluetun's kill-switch firewall rules (no network
  request). It is the tunnel's entry address; a provider may send traffic out
  from another one. A reconnect
  to another server rewrites the file; a gluetun restart removes it until the
  kill switch allows a server again. A dead handshake with the rule still in
  place does **not** empty it: gluetun's healthcheck is what notices that.
  Without `host_check_url`, verify does not compare the exit with this
  machine's IP.
- **`publicip_api` (`gluetun:publicip`):** gluetun's own lookup through the
  tunnel (`PUBLICIP_FILE`), with the service you name. glove picks none.

verify's `exit-confirmed` reads that file. observe's `exit_identity: auto`
mounts the volume **read-only** into the one gate that polls the exit only (vpn's
`shares: [exit]` export); the harness never sees it.
