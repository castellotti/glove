#!/usr/bin/env bash
# Live (v3 M7): the playwright browser sidecar end to end.
#
#   bash tests/integration/test_playwright.sh [headless|novnc|control|vibe|claude-code]   (default: headless)
#   RT=podman …                                                                # Podman
#
#   headless  Pi, direct egress, observe + filter: hardening, confinement,
#             browsing, flows, a filter block, the SSRF guard
#   novnc     Pi, direct egress: the above minus observe, plus loopback-only
#             VNC, `glove playwright view` and server-side view-only
#   control   novnc with allow_control: the full password's click lands
#   vibe      Vibe, headless, direct egress: the allowlist hides the rest
#   claude-code  Claude Code, headless, direct egress, observe: the allowlist
#             is allow rules, every other known tool a managed deny
#   SANDBOX=off … runs any case with `chromium_sandbox: off`
#
# A throwaway session dir (llm → the tool-driving stub) runs
# tests/integration/playwright_live.py. Needs internet (example.com via the
# direct egress). Uses a throwaway GLOVE_HOME; tears everything down (KEEP=1
# leaves the stack up).
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RT="${RT:-docker}"
CASE="${1:-headless}"
PORT="${STUB_PORT:-18085}"
. "$ROOT/tests/integration/lib_session.sh"
driver_init pw
stub_llm "$CASE" "$PORT"
start_stub "$PORT" "$TMPROOT/stub.log" || exit 1
HARNESS=pi; EXTRA=""; PW="{}"
case "$CASE" in
  headless) EXTRA=$'  observe: {}\n  filter: {}\n' ;;
  novnc)    PW="{mode: novnc}" ;;
  control)  PW="{mode: novnc, allow_control: true}" ;;
  vibe)     HARNESS=vibe ;;
  claude-code) HARNESS=claude-code; EXTRA=$'  observe: {}\n' ;;
  *) echo "unknown case $CASE" >&2; exit 2 ;;
esac
# SANDBOX=off: Chromium without its sandbox (the container is the only boundary)
if [ "${SANDBOX:-on}" = off ]; then IN="${PW#\{}"; IN="${IN%\}}"; PW="{${IN}${IN:+, }chromium_sandbox: \"off\"}"; fi
mkdir -p "$S/work"
printf 'glove: 3\ntemplate: test\nruntime: %s\n'"${ENFORCER:+enforcer: $ENFORCER\\n}"'harness: %s\nextensions:\n  llm: %s\n  direct: {}\n  playwright: %s\n%s' \
  "$RT" "$HARNESS" "$LLM" "$PW" "$EXTRA" > "$S/glove-session.yml"
echo "== runtime $RT, case $CASE"
( cd "$S" && STUB_LOG="$TMPROOT/stub.log" uv run --quiet --project "$ROOT" python "$ROOT/tests/integration/playwright_live.py" . )
RC=$?
SID="$(cat "$S/.glove/id" 2>/dev/null)"
LEFT="$($RT ps -aq --filter name=glove-$SID-)$($RT network ls -q --filter name=glove-$SID-)"
if [ -n "$LEFT" ] && [ -z "${KEEP:-}" ]; then echo "  FAIL leftovers: $LEFT"; RC=1; else echo "  PASS nothing left running"; fi
exit $RC
