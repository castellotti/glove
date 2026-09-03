#!/usr/bin/env bash
# Phase 2 integration checks (PLAN §8) — nono enforcer inside the real Pi image.
#
# These run against Docker with the shipping `glove/pi:0.3.0` image and the
# policies glove renders for a session. They exercise ring 1 (the kernel policy)
# directly via `nono wrap`/`nono run` — i.e. exactly what the Pi enforcer
# extension prepends to every shell command — WITHOUT needing an LLM or the TUI.
# The LLM/TUI-dependent checks (trivial prompt end-to-end, browser_navigate) are
# noted at the bottom and must be run manually against a live model.
#
# Usage:  bash tests/integration/test_pi_nono.sh
# Requires: docker, and `glove build pi` (or `docker build` of the pi harness).
# NOTE: no `pipefail` — `docker ... | grep -q` makes grep close the pipe on the
# first match, SIGPIPE-killing docker; under pipefail that non-zero would mask a
# real match. We want the pipeline status to be grep's.
set -u

IMAGE="${GLOVE_PI_IMAGE:-glove/pi:0.3.0}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORKDIR="$(mktemp -d)"
HOMEDIR="$(mktemp -d)"
GLOVE_HOME="$(mktemp -d)"
export GLOVE_HOME
PASS=0 FAIL=0

# Mirror the real glove hardening set, with /work and /home/agent as writable
# bind mounts (as compose renders them) on an otherwise read-only rootfs. The
# Pi config subdir is pre-created so nono grants it (it skips nonexistent dirs).
mkdir -p "$HOMEDIR/.pi/agent"
hardened=(--rm --cap-drop ALL --security-opt no-new-privileges:true --user 1000:1000
          --read-only --tmpfs /tmp -w /work
          -v "$WORKDIR:/work" -v "$HOMEDIR:/home/agent"
          -e HOME=/home/agent -e GLOVE_LLM_API_KEY=sk-INTEGRATION-SECRET)

ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

# --- render real glove policies for a pi session -----------------------------
echo "== rendering glove policies (glove pi --dry-run) =="
( cd "$WORKDIR" && uv run --project "$ROOT" glove init pi >/dev/null \
  && uv run --project "$ROOT" glove pi --add-dir "$WORKDIR:rw" --dry-run >/dev/null )
ENVID="$(basename "$WORKDIR")"
POLDIR="$GLOVE_HOME/envs/$ENVID/sessions/$ENVID/enforcer"
ls "$POLDIR"/*.json >/dev/null 2>&1 && ok "policies rendered to $POLDIR" || { bad "no policies rendered"; exit 1; }

MNT=(-v "$POLDIR:/etc/glove/enforcer:ro")
TOOL=(nono wrap -s --allow-cwd --profile /etc/glove/enforcer/tool.json -- bash -lc)
HARNESS=(nono run -s --allow-cwd --profile /etc/glove/enforcer/harness.json -- bash -lc)

run_tool()    { docker run "${hardened[@]}" "${MNT[@]}" "$IMAGE" "${TOOL[@]}" "$1" 2>&1; }
run_harness() { docker run "${hardened[@]}" "${MNT[@]}" "$IMAGE" "${HARNESS[@]}" "$1" 2>&1; }

echo "== ring-1 tool policy (shell commands) =="
run_tool 'echo hi > /work/f && cat /work/f' | grep -q '^hi$' && ok "write /work" || bad "write /work"
run_tool 'mkdir -p /home/agent/.pi/agent; ls /home/agent/.pi/agent' | grep -qi 'permission denied' \
  && ok "read harness home -> denied" || bad "harness home not denied"
run_tool 'curl -sS -m 4 http://1.1.1.1 >/dev/null 2>&1; echo rc=$?' | grep -q 'rc=[^0]' \
  && ok "network blocked" || bad "network not blocked"
out="$(run_tool 'env | grep -i -e key -e secret || echo NONE')"; echo "$out" | grep -q 'NONE' \
  && ok "secrets stripped from env" || bad "secret leaked: $out"
run_tool 'echo x > /etc/pwn 2>&1; echo rc=$?' | grep -q 'rc=[^0]' && ok "write /etc denied" || bad "write /etc allowed"
run_tool 'apt-get update 2>&1; echo rc=$?' | tail -1 | grep -q 'rc=[^0]' && ok "apt-get fails" || bad "apt-get succeeded"
run_tool 'sudo -n true 2>&1; echo rc=$?' | grep -q 'rc=[^0]' && ok "sudo fails" || bad "sudo succeeded"

echo "== malicious-extension drill (all four must fail) =="
run_tool 'curl -sS -m 4 https://example.com >/dev/null 2>&1; echo rc=$?' | grep -q 'rc=[^0]' \
  && ok "(a) fetch evil -> blocked" || bad "(a) fetch succeeded"
run_tool 'mkdir -p /home/agent/.ssh && echo k > /home/agent/.ssh/x 2>&1; echo rc=$?' | grep -q 'rc=[^0]' \
  && ok "(b) write ~/.ssh -> denied" || bad "(b) wrote ~/.ssh"
run_tool 'cat /etc/shadow >/dev/null 2>&1; echo rc=$?' | grep -q 'rc=[^0]' \
  && ok "(c) read /etc/shadow -> denied" || bad "(c) read /etc/shadow"
run_tool 'echo "${GLOVE_LLM_API_KEY:-EMPTY}"' | grep -q 'EMPTY' \
  && ok "(d) LLM key unreadable" || bad "(d) LLM key leaked"

echo "== ring-1 harness policy (harness process) =="
run_harness 'echo cfg > /home/agent/.pi/agent/x && echo wrote_home_ok' | grep -q 'wrote_home_ok' \
  && ok "harness writes its config home" || bad "harness cannot write config home"
# nested: a tool-wrapped command under the harness cannot read what the harness wrote
docker run "${hardened[@]}" "${MNT[@]}" "$IMAGE" "${HARNESS[@]}" \
  'echo topsecret > /home/agent/.pi/agent/t && nono wrap -s --allow-cwd --profile /etc/glove/enforcer/tool.json -- bash -lc "cat /home/agent/.pi/agent/t 2>&1"' \
  2>&1 | grep -qi 'permission denied' && ok "nested tool denied harness transcript" || bad "nested tool read transcript"

echo "== entrypoint fail-closed =="
docker run --rm -v "$POLDIR:/etc/glove/enforcer:ro" --entrypoint /opt/glove/entrypoint.sh "$IMAGE" true >/dev/null 2>&1 \
  && ok "entrypoint validates good policies and execs" || bad "entrypoint rejected valid policies"
BADDIR="$(mktemp -d)"; printf '{ this is not valid json ' > "$BADDIR/harness.json"; printf '{}' > "$BADDIR/tool.json"
docker run --rm -v "$BADDIR:/etc/glove/enforcer:ro" --entrypoint /opt/glove/entrypoint.sh "$IMAGE" true >/dev/null 2>&1 \
  && bad "entrypoint ran with an invalid policy" || ok "entrypoint fails closed on invalid policy"
rm -rf "$BADDIR"

rm -rf "$WORKDIR" "$HOMEDIR" "$GLOVE_HOME"
echo
echo "== RESULT: $PASS passed, $FAIL failed =="
echo "Manual (need a live LLM): the harness completes a trivial -p prompt (credential path);"
echo "browser_navigate via the Pi tool opens the host Chrome; curl to the browser sidecar from a shell fails."
[ "$FAIL" -eq 0 ]
