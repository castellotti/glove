# vpn

Fills the `egress` slot with a [gluetun](https://github.com/qdm12/gluetun) VPN
tunnel. gluetun is the only container on the session's `wan` network; its
kill-switch firewall drops anything that does not go through the tunnel, and
egress consumers (`search`, `webfetch`) reach the internet only through its
HTTP proxy on the internal egress network. Flows are labelled `route: vpn`.

```yaml
extensions:
  vpn:
    provider: mullvad                      # any gluetun provider name, or `custom`
    wireguard_key: keychain:my-vpn-wg-key  # store it: glove keychain set my-vpn-wg-key
    addresses: 10.64.0.2/32                # when the provider needs WIREGUARD_ADDRESSES
    countries: [Sweden]
```

| setting | meaning |
|---|---|
| `provider` | gluetun's `VPN_SERVICE_PROVIDER`, or `custom` (then `public_key` and `endpoint: ip:port`) |
| `type` | `wireguard` (default) or `openvpn` (`openvpn_user`/`openvpn_password` refs) |
| `wireguard_key` | Keychain/env reference to the WireGuard private key |
| `countries`, `cities`, `hostnames` | gluetun server selection |
| `register_hook` | see below |
| `check_url` | echo service for the leak check (default `https://am.i.mullvad.net/ip`) |

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
```

At every `glove up` glove runs it on this machine with the account username
and password on stdin (one per line). It must print exactly these lines on
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
problems), then `exit-ip-differs`: the IP an echo service sees through the
proxy must differ from this machine's public IP. Either failure stops the
session's sidecars; nothing starts half-tunnelled.
