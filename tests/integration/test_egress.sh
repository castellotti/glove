#!/usr/bin/env bash
# Live (v3 M4): an egress provider + search + webfetch, end to end.
#
#   bash tests/integration/test_egress.sh direct|tor          # Docker
#   HARNESS=vibe|claude-code bash tests/integration/test_egress.sh direct   # the MCP sidecars (default: pi)
#   OBSERVE=1 …                                                # with observe: the fetcher's flows
#   RT=podman bash tests/integration/test_egress.sh tor       # Podman
#   VPN_SETTINGS='{provider: …, wireguard_key: keychain:…}' bash tests/integration/test_egress.sh vpn
#   VPN_SETTINGS='{provider: custom, register_hook: local/hook.sh, register_user: keychain:…,
#                  register_pass: keychain:…}' VPN_LOCAL=<dir with the hook> bash … vpn
#   FAIL_EXIT=1 bash tests/integration/test_egress.sh tor|vpn  # a failing exit check stops the sidecars
#
# A throwaway session dir (llm → the tool-driving stub on the host) runs
# tests/integration/egress_live.py: sidecars up + verify (the exitcheck hook for
# vpn/tor), wan holds only the egress provider, SearXNG and the harness network
# have no direct internet, the search-mcp/webfetch-mcp/proxy endpoints work from the harness
# network, and the harness's search / fetch tools work through the egress
# (the search-mcp and fetcher sidecars; Claude Code's own WebFetch through the proxy).
# Secrets stay in the Keychain: glove resolves the refs in memory. Uses a
# throwaway GLOVE_HOME; tears everything down.
set -u
ROUTE="${1:?usage: test_egress.sh direct|tor|vpn}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RT="${RT:-docker}"
PORT="${STUB_PORT:-18082}"
HARNESS="${HARNESS:-pi}"
. "$ROOT/tests/integration/lib_session.sh"
driver_init "egress-$ROUTE"
stub_llm "$HARNESS" "$PORT"
start_stub "$PORT" "$TMPROOT/stub.log" || exit 1
case "$ROUTE" in
  direct|tor) EG="  $ROUTE: {}" ;;
  vpn) EG="  vpn: ${VPN_SETTINGS:?set VPN_SETTINGS to the vpn extension settings (flow YAML)}" ;;
  *) echo "route must be direct|tor|vpn" >&2; exit 2 ;;
esac
DRIVER=egress_live.py
if [ -n "${FAIL_EXIT:-}" ]; then
  # FAIL_EXIT: a host_check_url that names no IP address (exit_fail_live.py: verify must
  # fail and glove must stop the sidecars)
  [ "$ROUTE" = direct ] && { echo "FAIL_EXIT needs tor or vpn" >&2; exit 2; }
  EG="${EG%\}}"; [ "${EG%\{}" = "$EG" ] && EG="$EG, "
  EG="${EG}host_check_url: https://on.quad9.net/}"; DRIVER=exit_fail_live.py
fi
OBS=""; [ -n "${OBSERVE:-}" ] && OBS=$'  observe: {}\n'
mkdir -p "$S/work"
if [ -n "${VPN_LOCAL:-}" ]; then cp -R "$VPN_LOCAL" "$S/local"; fi
printf 'glove: 3\ntemplate: test\nruntime: %s\n'"${ENFORCER:+enforcer: $ENFORCER\\n}"'harness: %s\nextensions:\n  llm: %s\n%s\n  search: {}\n  webfetch: {}\n%s' \
  "$RT" "$HARNESS" "$LLM" "$EG" "$OBS" > "$S/glove-session.yml"
echo "== runtime $RT, route $ROUTE, harness $HARNESS${OBSERVE:+, observe}"
( cd "$S" && uv run --quiet --project "$ROOT" python "$ROOT/tests/integration/$DRIVER" . )
RC=$?
echo "== stub log (tool calls)"; grep -E 'tools=|->' "$TMPROOT/stub.log" | sort | uniq -c | sed 's/^/  /'
SID="$(cat "$S/.glove/id" 2>/dev/null)"
LEFT="$($RT ps -aq --filter name=glove-$SID-)$($RT network ls -q --filter name=glove-$SID-)"
if [ -n "$LEFT" ]; then echo "  FAIL leftovers: $LEFT"; RC=1; else echo "  PASS nothing left running"; fi
exit $RC
