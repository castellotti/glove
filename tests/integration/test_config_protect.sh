#!/usr/bin/env bash
# Live: the harness's own config is read-only to the agent and the project's
# never loads, under any enforcer and runtime, against the host llm stub.
#
#   bash tests/integration/test_config_protect.sh [pi|vibe|claude-code] [enforcer]   (default: pi nono)
#   RT=podman bash tests/integration/test_config_protect.sh vibe nono
#
# See config_protect_live.py for the checks.
set -u
HARNESS="${1:-pi}"; ENF="${2:-nono}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMPROOT="$(mktemp -d)"; S="$TMPROOT/protect"; export GLOVE_HOME="$TMPROOT/gh"
. "$ROOT/tests/integration/lib_session.sh"
STUB=
trap '[ -n "$STUB" ] && kill $STUB 2>/dev/null; rm -rf "$TMPROOT"' EXIT

stub_session "$S" "$HARNESS" "$ENF" || exit 1
uv run --project "$ROOT" python "$ROOT/tests/integration/config_protect_live.py" "$S"
