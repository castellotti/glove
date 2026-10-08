#!/usr/bin/env bash
# Live (v3 M2): the `llm` extension at `location: lan` against a real server.
#
#   bash tests/integration/test_llm_lan.sh <host:port> [<keychain-service>] [<provider>] [<capabilities>]
#
# Renders a throwaway Pi session with
#   llm: {provider: <provider|openai-compatible>, location: lan, endpoint: <host:port>,
#         model: auto, capabilities: <capabilities|auto>, api_key: keychain:<service>}
# then runs glove's launch path (tests/integration/llm_live.py): `model: auto`
# and `capabilities: auto` resolve through the forwarder from a throwaway
# container (the host never contacts the server itself), models.json is
# rendered, and Pi answers one prompt. The key is read from the Keychain in
# memory and handed only to the llm-auth sidecar (the harness gets a
# placeholder); it is never printed.
# PASS requires models.json `input` to contain "image" (vision reported).
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENDPOINT="${1:?usage: $0 <host:port> [<keychain-service>] [<provider>] [<capabilities>]}"
SERVICE="${2:-}"
PROVIDER="${3:-openai-compatible}"
CAPS="${4:-auto}"
. "$ROOT/tests/integration/lib_session.sh"
driver_init llmlan
uv run --project "$ROOT" glove new minimal "$S" >/dev/null
KEY=""; [ -n "$SERVICE" ] && KEY=", api_key: keychain:$SERVICE"
printf 'glove: 3\ntemplate: minimal\nharness: pi\nextensions:\n  llm: {provider: %s, location: lan, endpoint: "%s", model: auto, capabilities: %s%s}\n' \
  "$PROVIDER" "$ENDPOINT" "$CAPS" "$KEY" > "$S/glove-session.yml"
OUT="$(uv run --project "$ROOT" python "$ROOT/tests/integration/llm_live.py" "$S" \
  "Describe in one sentence what you are." 2>&1 | grep -v '^ Container\|Network \|^#\|^ ✔')"
rc=$?
echo "$OUT"
echo
if echo "$OUT" | grep -q '"image"' && echo "$OUT" | grep -q 'model: auto →'; then
  echo "== RESULT: PASS (model: auto resolved; vision reported; Pi answered via glove-<id>-llm)"
else
  echo "== RESULT: FAIL"; rc=1
fi
exit $rc
