#!/usr/bin/env bash
# Live: `glove playwright login` + `storage_state` — a stand-in sign-on site
# (stubs/login_site.js), a real headless host Chrome signing in to it (CDP over
# a pipe), the session's browser seeded with what it stored, through the
# `corporate` egress.
#
#   bash tests/integration/test_playwright_login.sh [harness] [enforcer]   (default: pi, the runtime's default)
#   RT=podman SANDBOX=off bash tests/integration/test_playwright_login.sh pi nono
#
# SANDBOX=off runs Chromium without its sandbox (`chromium_sandbox: "off"`; the
# container is the only boundary): Podman can't apply its seccomp profile.
#
# Needs a Chrome/Chromium on this machine (glove's discovery: a system Chrome,
# else Playwright's Chrome for Testing). Writes three throwaway Keychain items
# (glove-test-pwlogin-<pid>-*), removed on exit. See playwright_login_live.py
# for the checks.
set -u
H="${1:-pi}"
RT="${RT:-docker}"
ENF="${2:-$([ "$RT" = podman ] && echo nono || echo nono+srt)}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/tests/integration/lib_session.sh"
driver_init playwright-login
P="glove-test-pwlogin-$$"
export PWL_STATE="$P-state" PWL_D="$P-chat-d" PWL_XOXC="$P-chat-xoxc"
# the stand-in's own network: a private range the corporate egress must allow
# by CIDR too (a name alone never passes its guard to a private address)
export PWL_SUBNET="${PWL_SUBNET:-10.213.78.0/24}"
cleanup_keychain() {
  for svc in "$PWL_STATE" "$PWL_D" "$PWL_XOXC"; do
    security delete-generic-password -s "$svc" >/dev/null 2>&1
    i=1; while security delete-generic-password -s "$svc.part$i" >/dev/null 2>&1; do i=$((i + 1)); done
  done
}
ON_EXIT=cleanup_keychain
# an empty state, so the first launch seeds nothing (the control)
printf '{"cookies":[],"origins":[]}' | uv run --quiet --project "$ROOT" glove keychain set --stdin "$PWL_STATE" \
  >/dev/null || exit 1

stub_session "$S" "$H" "$ENF" "$(cat <<YML
  corporate:
    allow_domains: [corp.test, "*.corp.test", chat.test, "*.chat.test", tracker.test]
    allow_cidrs: ["$PWL_SUBNET"]
  playwright:
    chromium_sandbox: "${SANDBOX:-on}"
    storage_state: "keychain:$PWL_STATE"
    login:
      start_url: http://idp.corp.test/login
      domains: [corp.test, "*.corp.test"]
      capture:
        $PWL_D: {cookie: {domain: chat.test, name: d}}
        $PWL_XOXC: {storage: {origin: "http://app.chat.test", key: cfg, match: "xoxc-[0-9a-z-]+"}}
YML
)
" || exit 1

( cd "$S" && uv run --quiet --project "$ROOT" python "$ROOT/tests/integration/playwright_login_live.py" . )
exit $?
