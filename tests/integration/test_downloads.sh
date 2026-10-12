#!/usr/bin/env bash
# Live (round 10): web_download end to end, per harness.
#
#   bash tests/integration/test_downloads.sh direct|vpn          # Pi on Docker
#   HARNESS=vibe|claude-code bash tests/integration/test_downloads.sh direct
#   VPN_SETTINGS='{…}' [VPN_LOCAL=<dir>] bash … vpn                # as test_egress.sh
#   OCR=1 …       also the ocr extension: glove-ocr reads the downloaded PDF
#   BIG=1 …       also a large file as a job: Debian's netinst ISO (~750 MB; BIG=dvd: its first DVD,
#                 ~4 GB); off by default (no run downloads a large file unless asked)
#   RT=podman …   Podman
#
# A throwaway session dir (llm → the tool-driving stub; observe + filter;
# webfetch {downloads: work}) runs tests/integration/downloads_live.py. Uses a
# throwaway GLOVE_HOME; tears everything down.
set -u
ROUTE="${1:?usage: test_downloads.sh direct|vpn}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RT="${RT:-docker}"
PORT="${STUB_PORT:-18086}"
HARNESS="${HARNESS:-pi}"
. "$ROOT/tests/integration/lib_session.sh"
driver_init "downloads-$ROUTE"
stub_llm "$HARNESS" "$PORT"
start_stub "$PORT" "$TMPROOT/stub.log" || exit 1
case "$ROUTE" in
  direct) EG="  direct: {}" ;;
  vpn) EG="  vpn: ${VPN_SETTINGS:?set VPN_SETTINGS to the vpn extension settings (flow YAML)}" ;;
  *) echo "route must be direct|vpn" >&2; exit 2 ;;
esac
OCR_EXT=""; [ -n "${OCR:-}" ] && OCR_EXT=$'  ocr: {}\n'
mkdir -p "$S/work"
if [ -n "${VPN_LOCAL:-}" ]; then cp -R "$VPN_LOCAL" "$S/local"; fi
printf 'glove: 3\ntemplate: test\nruntime: %s\nharness: %s\nextensions:\n  llm: %s\n%s\n  webfetch: {downloads: work}\n  observe: {}\n  filter: {}\n%s' \
  "$RT" "$HARNESS" "$LLM" "$EG" "$OCR_EXT" > "$S/glove-session.yml"
echo "== runtime $RT, route $ROUTE, harness $HARNESS"
( cd "$S" && uv run --quiet --project "$ROOT" python "$ROOT/tests/integration/downloads_live.py" . )
RC=$?
SID="$(cat "$S/.glove/id" 2>/dev/null)"
LEFT="$($RT ps -aq --filter name=glove-$SID-)$($RT network ls -q --filter name=glove-$SID-)"
if [ -n "$LEFT" ]; then echo "  FAIL leftovers: $LEFT"; RC=1; else echo "  PASS nothing left running"; fi
exit $RC
