#!/usr/bin/env bash
# Live (v3 M4): an egress provider + search + webfetch, end to end.
#
#   bash tests/integration/test_egress.sh direct|tor          # Docker
#   RT=podman bash tests/integration/test_egress.sh tor       # Podman
#   VPN_SETTINGS='{provider: …, wireguard_key: keychain:…}' bash tests/integration/test_egress.sh vpn
#   VPN_SETTINGS='{provider: custom, register_hook: local/hook.sh, register_user: keychain:…,
#                  register_pass: keychain:…}' VPN_LOCAL=<dir with the hook> bash … vpn
#
# A throwaway session dir (llm → the tool-driving stub on the host) runs
# tests/integration/egress_live.py: sidecars up + verify (exit-ip-differs for
# vpn/tor), wan holds only the egress provider, SearXNG and the harness network
# have no direct internet, the search/proxy endpoints work from the harness
# network, and Pi's web_search / web_fetch tools work through the egress.
# Secrets stay in the Keychain: glove resolves the refs in memory. Uses a
# throwaway GLOVE_HOME; tears everything down.
set -u
ROUTE="${1:?usage: test_egress.sh direct|tor|vpn}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RT="${RT:-docker}"
PORT="${STUB_PORT:-18082}"
TMPROOT="$(mktemp -d)"; S="$TMPROOT/egress-$ROUTE"; export GLOVE_HOME="${GLOVE_HOME:-$TMPROOT/gh}"
python3 "$ROOT/tests/integration/stubs/llm_stub.py" "$PORT" > "$TMPROOT/stub.log" 2>&1 &
STUB=$!; disown "$STUB"
trap 'kill $STUB 2>/dev/null; rm -rf "$TMPROOT"' EXIT
sleep 1
case "$ROUTE" in
  direct|tor) EG="  $ROUTE: {}" ;;
  vpn) EG="  vpn: ${VPN_SETTINGS:?set VPN_SETTINGS to the vpn extension settings (flow YAML)}" ;;
  *) echo "route must be direct|tor|vpn" >&2; exit 2 ;;
esac
mkdir -p "$S/work"
if [ -n "${VPN_LOCAL:-}" ]; then cp -R "$VPN_LOCAL" "$S/local"; fi
printf 'glove: 3\ntemplate: test\nruntime: %s\nharness: pi\nextensions:\n  llm: {provider: llama.cpp, location: host, endpoint: "127.0.0.1:%s", model: auto}\n%s\n  search: {}\n  webfetch: {}\n' \
  "$RT" "$PORT" "$EG" > "$S/glove-session.yml"
echo "== runtime $RT, route $ROUTE"
( cd "$S" && uv run --quiet --project "$ROOT" python "$ROOT/tests/integration/egress_live.py" . )
RC=$?
echo "== stub log (tool calls)"; grep -E 'tools=|->' "$TMPROOT/stub.log" | sort | uniq -c | sed 's/^/  /'
SID="$(cat "$S/.glove/id" 2>/dev/null)"
LEFT="$($RT ps -aq --filter name=glove-$SID-)$($RT network ls -q --filter name=glove-$SID-)"
if [ -n "$LEFT" ]; then echo "  FAIL leftovers: $LEFT"; RC=1; else echo "  PASS nothing left running"; fi
exit $RC
