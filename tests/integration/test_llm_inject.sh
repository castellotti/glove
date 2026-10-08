#!/usr/bin/env bash
# Live: the LLM key stays in glove's llm-auth sidecar and never enters the
# harness, against the host llm stub (which answers only with the real key).
#
#   bash tests/integration/test_llm_inject.sh [pi|vibe|claude-code|claude-code-oauth] [enforcer]
#   RT=podman bash tests/integration/test_llm_inject.sh pi
#
# claude-code-oauth: a subscription token (`provider: anthropic, auth: oauth`,
# observe on), against a stand-in for api.anthropic.com the driver adds to the
# session (llm_inject_live.stand_in) instead of the host stub.
# The enforcer defaults to the runtime's (nono+srt on Docker, nono where srt
# can't run). See llm_inject_live.py for the checks.
set -u
HARNESS="${1:-pi}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/tests/integration/lib_session.sh"
driver_init inject

runtime_facts
ENF="${2:-$([ -n "$SRT_REFUSED" ] && echo nono || echo nono+srt)}"
stub_session "$S" "$HARNESS" "$ENF" "$([ "$HARNESS" = claude-code-oauth ] && echo '  observe: {}\n')" || exit 1
uv run --project "$ROOT" python "$ROOT/tests/integration/llm_inject_live.py" "$S" ${STUB_PY:+"$S.stub.log"}
