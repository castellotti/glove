"""netgate — glove's instrumented forwarder (network observability, M1).

Runs *inside* the gate containers, never on the host, and is stdlib-only so the
image is just a Python runtime plus this package. Two roles:

- ``forward`` — one per observed service, a drop-in for that service's ``socat``
  sidecar: same container name, networks and listen port. Forwards TCP to the
  configured target and emits flow records (open / ~1 Hz update / close) as
  datagrams to the collector. It exposes nothing but the forwarded port.
- ``collect`` — ``glove-<session>-netgate``, ``network_mode: none``. The single
  writer of ``net/flows.ndjson`` (rotated) and ``net/status.json``.

Telemetry fails open: a missing, slow or broken collector costs records, never
traffic. See ``docs/planning/network-observability.md``.
"""

GATE_VERSION = "0.1.0"
SCHEMA_VERSION = 1

# In-container paths shared by the render path (glove/observe.py) and the gate.
EVENTS_DIR = "/run/glove-netgate"
EVENTS_SOCKET = f"{EVENTS_DIR}/events.sock"
NET_DIR = "/var/lib/glove/net"
CONTROL_DIR = "/etc/glove/netgate-control"  # rules.json lives here, read-only
RULES_FILE = f"{CONTROL_DIR}/rules.json"

# Value sets validated on the host (glove/observe.py) and accepted by the gate.
SCOPES = ("local", "tunnelled", "direct")
MODES = ("tcp", "http-proxy")
# What a `chain:` upstream actually is. glove cannot tell a VPN proxy from a
# plain one, so the operator declares it; `direct` makes every flow loud.
ROUTES = ("vpn", "tor", "direct")
CLIENTS = ("searxng", "playwright", "unknown")  # labels for peers off the internal network
RESOLVE_MODES = ("in-tunnel", "none")
RECORD_MODES = ("metadata", "full")

# flows.ndjson rotation defaults
ROTATE_BYTES = 64 * 1024 * 1024
ROTATE_KEEP = 8
