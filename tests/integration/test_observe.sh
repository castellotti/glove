#!/usr/bin/env bash
# Live (v3 M5): observe + filter end to end — replaces the v2 test_netgate_m1/m2.sh.
#
#   bash tests/integration/test_observe.sh [direct|tor]          # Docker
#   RT=podman bash tests/integration/test_observe.sh direct      # Podman
#   VPN_SETTINGS='{…}' [VPN_LOCAL=<dir>] bash … vpn             # as test_egress.sh vpn
#
# A throwaway session dir (llm → the tool-driving stub on the host, its key in
# llm-auth; egress +
# search + webfetch + observe + filter) runs tests/integration/observe_live.py:
# every forwarder a netgate, SearXNG reaching egress only through its gate, Pi's
# tool calls recorded as flows, transcripts exported, a `glove filter block`
# enforced and recorded, then revocation when `filter:` is removed. Uses a
# throwaway GLOVE_HOME; tears everything down (KEEP=1 leaves the stack up).
set -u
ROUTE="${1:-direct}"
EG="$ROUTE: {}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RT="${RT:-docker}"
PORT="${STUB_PORT:-18083}"
. "$ROOT/tests/integration/lib_session.sh"
driver_init "observe-$ROUTE"
stub_llm pi "$PORT"
start_stub "$PORT" "$TMPROOT/stub.log" || exit 1
case "$ROUTE" in
  direct|tor) ;;
  vpn) EG="vpn: ${VPN_SETTINGS:?set VPN_SETTINGS to the vpn extension settings (flow YAML)}" ;;
  *) echo "route must be direct|tor|vpn" >&2; exit 2 ;;
esac
mkdir -p "$S/work"
if [ -n "${VPN_LOCAL:-}" ]; then cp -R "$VPN_LOCAL" "$S/local"; fi
printf 'glove: 3\ntemplate: test\nruntime: %s\n'"${ENFORCER:+enforcer: $ENFORCER\\n}"'harness: pi\nextensions:\n  llm: %s\n  %s\n  search: {}\n  webfetch: {}\n  observe: {}\n  filter: {}\n' \
  "$RT" "$LLM" "$EG" > "$S/glove-session.yml"
echo "== runtime $RT, route $ROUTE"
( cd "$S" && uv run --quiet --project "$ROOT" python "$ROOT/tests/integration/observe_live.py" . )
RC=$?
SID="$(cat "$S/.glove/id" 2>/dev/null)"
LEFT="$($RT ps -aq --filter name=glove-$SID-)$($RT network ls -q --filter name=glove-$SID-)$($RT volume ls -q --filter name=glove-$SID-)"
if [ -n "$LEFT" ]; then echo "  FAIL leftovers: $LEFT"; RC=1; else echo "  PASS nothing left running"; fi
exit $RC
