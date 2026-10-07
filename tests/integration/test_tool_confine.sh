#!/usr/bin/env bash
# Live: the agent's own tools under the harness's hook, by the tool names the
# harness uses today (shell wrapped, file writes held to the write roots; Pi's
# built-in MCP off), against the host llm stub.
#
#   bash tests/integration/test_tool_confine.sh [pi|vibe] [enforcer]   (default: pi nono)
#   RT=podman bash tests/integration/test_tool_confine.sh vibe nono
#
# See tool_confine_live.py for the checks.
set -u
HARNESS="${1:-pi}"; ENF="${2:-nono}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMPROOT="$(mktemp -d)"; S="$TMPROOT/confine"; export GLOVE_HOME="$TMPROOT/gh"
. "$ROOT/tests/integration/lib_session.sh"
STUB=
trap '[ -n "$STUB" ] && kill $STUB 2>/dev/null; chmod -R u+w "$TMPROOT" 2>/dev/null; rm -rf "$TMPROOT"' EXIT

STUB_PORT="${STUB_PORT:-18092}" stub_session "$S" "$HARNESS" "$ENF" || exit 1
uv run --project "$ROOT" python "$ROOT/tests/integration/tool_confine_live.py" "$S"
