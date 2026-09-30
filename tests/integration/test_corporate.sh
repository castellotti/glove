#!/usr/bin/env bash
# Live (v3 M5): the corporate egress, with a public host standing in for a
# corporate one (example.org allowed, everything else refused). The real check
# — an internal host through the corporate VPN — is the operator's: see
# docs/planning or the corporate extension README, "Checking it live".
#
#   bash tests/integration/test_corporate.sh            # Docker
#   RT=podman bash tests/integration/test_corporate.sh  # Podman
#
# allow_cidrs covers the runtimes' host-gateway range (192.168.0.0/16) on
# purpose: the gate must refuse the host gateway anyway. Throwaway GLOVE_HOME;
# tears everything down.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RT="${RT:-docker}"
PORT="${STUB_PORT:-18084}"
TMPROOT="$(mktemp -d)"; S="$TMPROOT/corp"; export GLOVE_HOME="${GLOVE_HOME:-$TMPROOT/gh}"
python3 "$ROOT/tests/integration/stubs/llm_stub.py" "$PORT" > "$TMPROOT/stub.log" 2>&1 &
STUB=$!; disown "$STUB"
trap 'kill $STUB 2>/dev/null; rm -rf "$TMPROOT"' EXIT
sleep 1
mkdir -p "$S/work"
cat > "$S/glove-session.yml" <<YML
glove: 3
template: test
runtime: $RT
${ENFORCER:+enforcer: $ENFORCER}
harness: pi
extensions:
  llm: {provider: llama.cpp, location: host, endpoint: "127.0.0.1:$PORT", model: auto}
  corporate:
    allow_domains: [example.org]
    allow_cidrs: [192.168.0.0/16]
    tcp: [{name: web80, to: "example.org:80"}]
    probe_url: https://example.org/
  webfetch: {}
  observe: {}
YML
echo "== runtime $RT"
( cd "$S" && uv run --quiet --project "$ROOT" python "$ROOT/tests/integration/corporate_live.py" . )
RC=$?
SID="$(cat "$S/.glove/id" 2>/dev/null)"
[ -n "${KEEP:-}" ] && exit $RC
LEFT="$($RT ps -aq --filter name=glove-$SID-)$($RT network ls -q --filter name=glove-$SID-)$($RT volume ls -q --filter name=glove-$SID-)"
if [ -n "$LEFT" ]; then echo "  FAIL leftovers: $LEFT"; RC=1; else echo "  PASS nothing left running"; fi
exit $RC
