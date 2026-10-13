#!/usr/bin/env bash
# Live: a `skills` relay — the fixture plugin's scripts/api.py run in its relay
# sidecar, with its token from the Keychain, against a public bearer-token echo
# (httpbin.org) behind `direct` egress; the expiry → status → refresh → reload
# cycle with the harness left running.
#
#   bash tests/integration/test_skills_relay.sh [harness] [enforcer]   (default: pi, the runtime's default)
#   RT=podman bash tests/integration/test_skills_relay.sh pi nono
#
# It stores a throwaway login Keychain item (glove-test-skills-relay: a fake
# token, never a real one) and deletes it on the way out. See
# skills_relay_live.py for the checks.
set -u
H="${1:-pi}"
ENF="${2:-$([ "${RT:-docker}" = podman ] && echo nono || echo nono+srt)}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/tests/integration/lib_session.sh"
driver_init skills-relay
export SKILLS_RELAY_ITEM=glove-test-skills-relay
forget() { security delete-generic-password -s "$SKILLS_RELAY_ITEM" >/dev/null 2>&1; }
security add-generic-password -U -a "${USER:-glove}" -s "$SKILLS_RELAY_ITEM" -w expired-1 || exit 1

RELAY='{commands: {scripts/api.py: {hosts: [httpbin.org], allow: [whoami, other, home, fetch], out_flags: [-o], '
RELAY+="env: {API_TOKEN: {secret: \"keychain:$SKILLS_RELAY_ITEM\", refresh: local/mint.sh}, API_MODE: test}, "
RELAY+="files: {\"~/.config/demo/ws.json\": {template: local/ws.json.j2, secrets: {tok: \"keychain:$SKILLS_RELAY_ITEM\"}}}}}, "
RELAY+='check: ["scripts/api.py whoami"]}'
stub_session "$S" "$H" "$ENF" "  direct: {}\n  skills:\n    plugins:\n      demo: {path: skills/demo, skills: [greet], relay: $RELAY}\n" || { forget; exit 1; }
mkdir -p "$S/skills" "$S/local" && cp -R "$ROOT/tests/integration/fixtures/skills-plugin/demo" "$S/skills/demo"
printf '#!/bin/sh\n# a refresh hook: prints the new secret for the service it is given\necho good-2\n' > "$S/local/mint.sh"
chmod 755 "$S/local/mint.sh"
printf '{"token": "{{ secrets.tok }}"}\n' > "$S/local/ws.json.j2"
( cd "$S" && uv run --quiet --project "$ROOT" python "$ROOT/tests/integration/skills_relay_live.py" . )
rc=$?
forget
exit $rc
