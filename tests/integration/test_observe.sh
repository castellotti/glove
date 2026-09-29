#!/usr/bin/env bash
# Live (v3 M5): observe + filter end to end — replaces the v2 test_netgate_m1/m2.sh.
#
#   bash tests/integration/test_observe.sh [direct|tor]          # Docker
#   RT=podman bash tests/integration/test_observe.sh direct      # Podman
#
# A throwaway session dir (llm → the tool-driving stub on the host; egress +
# search + webfetch + observe + filter) runs tests/integration/observe_live.py:
# every forwarder a netgate, SearXNG reaching egress only through its gate, Pi's
# tool calls recorded as flows, transcripts exported, a `glove filter block`
# enforced and recorded, then revocation when `filter:` is removed. Uses a
# throwaway GLOVE_HOME; tears everything down.
set -u
ROUTE="${1:-direct}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RT="${RT:-docker}"
PORT="${STUB_PORT:-18083}"
TMPROOT="$(mktemp -d)"; S="$TMPROOT/observe-$ROUTE"; export GLOVE_HOME="${GLOVE_HOME:-$TMPROOT/gh}"
python3 "$ROOT/tests/integration/stubs/llm_stub.py" "$PORT" > "$TMPROOT/stub.log" 2>&1 &
STUB=$!; disown "$STUB"
trap 'kill $STUB 2>/dev/null; rm -rf "$TMPROOT"' EXIT
sleep 1
case "$ROUTE" in direct|tor) ;; *) echo "route must be direct|tor" >&2; exit 2 ;; esac
mkdir -p "$S/work"
printf 'glove: 3\ntemplate: test\nruntime: %s\nharness: pi\nextensions:\n  llm: {provider: llama.cpp, location: host, endpoint: "127.0.0.1:%s", model: auto}\n  %s: {}\n  search: {}\n  webfetch: {}\n  observe: {}\n  filter: {}\n' \
  "$RT" "$PORT" "$ROUTE" > "$S/glove-session.yml"
echo "== runtime $RT, route $ROUTE"
( cd "$S" && uv run --quiet --project "$ROOT" python "$ROOT/tests/integration/observe_live.py" . )
RC=$?
SID="$(cat "$S/.glove/id" 2>/dev/null)"
LEFT="$($RT ps -aq --filter name=glove-$SID-)$($RT network ls -q --filter name=glove-$SID-)$($RT volume ls -q --filter name=glove-$SID-)"
if [ -n "$LEFT" ]; then echo "  FAIL leftovers: $LEFT"; RC=1; else echo "  PASS nothing left running"; fi
exit $RC
