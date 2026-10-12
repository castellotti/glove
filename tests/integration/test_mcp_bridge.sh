#!/usr/bin/env bash
# Round 11: Vibe's glove-mcp-bridge (stdio → one Streamable-HTTP MCP session)
# in the real Vibe image, by its baked path and shebang, against the unit
# test's stand-in server (harnesses/vibe/tests/test_mcp_bridge.py), in glove's
# hardened throwaway (offline: its own loopback only).
#
#   bash tests/integration/test_mcp_bridge.sh        # RT=podman for Podman
set -u
RT="${RT:-docker}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/tests/integration/lib_session.sh"
image_driver
IMAGE="${GLOVE_VIBE_IMAGE:-$(ensure_image vibe)}" || exit 1
eval "$(uv run --quiet --project "$ROOT" python -c 'import shlex, sys
from glove.runtimes import get_runtime
rt, image, tests = sys.argv[1:]
print(shlex.join(get_runtime(rt).throwaway_argv(
    image, ["/t/test_mcp_bridge.py", "/opt/glove/bin/glove-mcp-bridge"], user="1000:1000",
    mounts=[(tests, "/t")], entrypoint="/usr/local/bin/python3")))' "$RT" "$IMAGE" "$ROOT/harnesses/vibe/tests")"
