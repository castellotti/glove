# exitcheck

A library extension, never selected on its own. It owns the egresses' exit
check, verify's `exit-confirmed`: `vpn` and `tor` require it and import its
`verify` hook into their own hooks module. It renders nothing.

Core runs the check as a `kind: hook` verify item and keeps the decision: a
raise (a bug included), a missing hook or no result fails it and stops the
session's sidecars (fail closed). The hook gets `glove.api.VerifyTools`, no
more: the egress proxy, a fetch through it from a throwaway probe container,
the check's own `argv` in its own sidecar `service`, and a retry with the
check's `retries`/`interval`.

## The check

The egress's own software must report one valid IP address for its exit:

| `source` | where the IP comes from | used by |
|---|---|---|
| `exec` | the check's `argv` prints it inside its sidecar `service` (what else it prints is withheld) | vpn: the exit file gluetun publishes |
| `url` | `url` answers it through the egress proxy as JSON: `ip_field` holds the IP, and every `expect` field must equal its value | tor: the Tor Project's check, `{IsTor: true}` |

A `url` answer that is not JSON (a fresh circuit's interstitial page) or no
answer is retried; a JSON answer is final.

With the operator's `host_check_url` (no default), that service, asked from
the host and through the egress, must see two different IPs, or the launch
stops ("a leak cannot be ruled out" when either side names no IP). It is the
only lookup of the host's own IP: glove picks no lookup service.
