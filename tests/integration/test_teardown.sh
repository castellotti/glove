#!/usr/bin/env bash
# Live: one harness per session (`glove up` twice, a killed client), git config
# from one owner, and nothing left after `glove down`, against the host llm stub.
#
#   bash tests/integration/test_teardown.sh [pi|vibe|claude-code] [enforcer]   (default: pi nono; RT=podman too)
#
# See teardown_live.py for the checks.
set -u
HARNESS="${1:-pi}"; ENF="${2:-nono}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMPROOT="$(mktemp -d)"; S="$TMPROOT/teardown"; export GLOVE_HOME="$TMPROOT/gh"
. "$ROOT/tests/integration/lib_session.sh"
STUB=
trap '[ -n "$STUB" ] && kill $STUB 2>/dev/null; rm -rf "$TMPROOT"' EXIT

stub_session "$S" "$HARNESS" "$ENF" 'git_config: {safe.directory: "*"}\n' || exit 1
uv run --project "$ROOT" python "$ROOT/tests/integration/teardown_live.py" "$S"
