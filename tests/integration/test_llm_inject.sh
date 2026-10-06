#!/usr/bin/env bash
# Live: the LLM key stays in glove's llm-auth sidecar and never enters the
# harness, against the host llm stub (which answers only with the real key).
#
#   bash tests/integration/test_llm_inject.sh [pi|vibe|claude-code] [enforcer]
#   RT=podman bash tests/integration/test_llm_inject.sh pi
#
# The enforcer defaults to the runtime's (nono+srt on Docker, nono where srt
# can't run). See llm_inject_live.py for the checks.
set -u
HARNESS="${1:-pi}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMPROOT="$(mktemp -d)"; S="$TMPROOT/inject"; export GLOVE_HOME="$TMPROOT/gh"
. "$ROOT/tests/integration/lib_session.sh"
STUB=
trap '[ -n "$STUB" ] && kill $STUB 2>/dev/null; rm -rf "$TMPROOT"' EXIT

runtime_facts
ENF="${2:-$([ -n "$SRT_REFUSED" ] && echo nono || echo nono+srt)}"
stub_session "$S" "$HARNESS" "$ENF" || exit 1
uv run --project "$ROOT" python "$ROOT/tests/integration/llm_inject_live.py" "$S" "$S.stub.log"
