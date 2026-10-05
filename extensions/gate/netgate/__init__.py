"""netgate — glove's instrumented forwarder (the `gate` extension's image).

Runs *inside* the gate containers, never on the host, and is stdlib-only so the
image is just a Python runtime plus this package. Two roles:

- ``forward`` — one per observed service, a drop-in for that service's ``socat``
  sidecar: same container name, networks and listen port. Forwards TCP to the
  configured target and emits flow records (open / ~1 Hz update / close) as
  datagrams to the collector. It exposes nothing but the forwarded port.
- ``collect`` — ``glove-<session>-netgate``, ``network_mode: none``. The single
  writer of ``net/flows.ndjson`` (rotated) and ``net/status.json``.

``forward --mode http-proxy --upstream direct`` is the ``corporate`` egress
provider: the gate resolves and dials the destination itself, under a static
default-block policy built from the operator's allowlist.

Telemetry fails open: a missing, slow or broken collector costs records, never
traffic. See ``docs/planning/network-observability.md``.
"""

import re

GATE_VERSION = "0.2.0"
SCHEMA_VERSION = 1

# In-container paths shared by the render path (extensions/gate/gatelib.py) and the gate.
EVENTS_DIR = "/run/glove-netgate"
EVENTS_SOCKET = f"{EVENTS_DIR}/events.sock"
NET_DIR = "/var/lib/glove/net"
CONTROL_DIR = "/etc/glove/netgate-control"  # rules.json lives here, read-only
RULES_FILE = f"{CONTROL_DIR}/rules.json"

# Value sets validated on the host (extensions/gate/gatelib.py) and accepted by the gate.
SCOPES = ("local", "tunnelled", "direct", "lan", "cloud")  # lan/cloud: the llm forwarder
MODES = ("tcp", "http-proxy")
# What a `chain:` upstream actually is. glove cannot tell a VPN proxy from a
# plain one, so the operator declares it; `direct` makes every flow loud.
ROUTES = ("vpn", "tor", "direct", "corporate")  # corporate: the host's corporate VPN
RESOLVE_MODES = ("in-tunnel", "none")
RECORD_MODES = ("metadata", "full")

# The label for peers that did not arrive on the harness ingress (gatelib picks
# the default). A label only, read by no policy; never `harness`, which only the
# ingress assigns.
CLIENT = re.compile(r"^[a-z][a-z0-9-]*\Z")  # an extension name (glove.extensions._NAME)


def client_problem(label: str) -> str | None:
    if CLIENT.fullmatch(label) and label != "harness":
        return None
    return f"a client label matches {CLIENT.pattern} and is not `harness`, got {label!r}"


# Forwarders re-announce `gate start` this often (a heartbeat); the collector
# writes an inferred `stop` for a run silent for RUN_LOST_AFTER.
ANNOUNCE_EVERY = 10.0
RUN_LOST_AFTER = 3 * ANNOUNCE_EVERY

# flows.ndjson rotation defaults
ROTATE_BYTES = 64 * 1024 * 1024
ROTATE_KEEP = 8
