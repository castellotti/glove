#!/usr/bin/env bash
# Phase 3 integration checks (PLAN §8) — nono enforcer + hook inside the real
# Vibe image. Confirms (1) the shipping glove/vibe:0.3.0 image enforces the same
# ring-1 policies as Pi, and (2) the baked /opt/glove/vibe-hook rewrites bash
# tool calls through the per-command wrapper (what Vibe's pre_tool hook invokes).
# The full LLM/TUI path (hook firing live, strict denial in the TUI) is manual.
#
# Usage:  bash tests/integration/test_vibe_nono.sh
# See NOTE in test_pi_nono.sh about `pipefail` and grep closing pipes.
set -u

IMAGE="${GLOVE_VIBE_IMAGE:-glove/vibe:0.3.0}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORKDIR="$(mktemp -d)"; HOMEDIR="$(mktemp -d)"; GLOVE_HOME="$(mktemp -d)"
export GLOVE_HOME
PASS=0 FAIL=0
mkdir -p "$HOMEDIR/.vibe"

hardened=(--rm --cap-drop ALL --security-opt no-new-privileges:true --user 1000:1000
          --read-only --tmpfs /tmp -w /work -v "$WORKDIR:/work" -v "$HOMEDIR:/home/agent"
          -e HOME=/home/agent -e GLOVE_LLM_API_KEY=sk-INTEGRATION-SECRET)

ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "== rendering glove policies (glove vibe --dry-run) =="
( cd "$WORKDIR" && uv run --project "$ROOT" glove init vibe >/dev/null \
  && uv run --project "$ROOT" glove vibe --dry-run >/dev/null )
ENVID="$(basename "$WORKDIR")"
POLDIR="$GLOVE_HOME/envs/$ENVID/sessions/$ENVID/enforcer"
ls "$POLDIR"/*.json >/dev/null 2>&1 && ok "policies rendered" || { bad "no policies"; exit 1; }
MNT=(-v "$POLDIR:/etc/glove/enforcer:ro")
run_tool() { docker run "${hardened[@]}" "${MNT[@]}" "$IMAGE" \
  nono wrap -s --allow-cwd --profile /etc/glove/enforcer/tool.json -- bash -lc "$1" 2>&1; }

echo "== ring-1 tool policy enforces in the vibe image =="
run_tool 'echo hi > /work/f && cat /work/f' | grep -q '^hi$' && ok "write /work" || bad "write /work"
run_tool 'mkdir -p /home/agent/.vibe; ls /home/agent/.vibe' | grep -qi 'permission denied' \
  && ok "read vibe home -> denied" || bad "vibe home not denied"
run_tool 'curl -sS -m 4 http://1.1.1.1 >/dev/null 2>&1; echo rc=$?' | grep -q 'rc=[^0]' \
  && ok "network blocked" || bad "network not blocked"
run_tool 'env | grep -i -e key -e secret || echo NONE' | grep -q 'NONE' \
  && ok "secrets stripped" || bad "secret leaked"

echo "== baked vibe-hook rewrites a bash tool call =="
HOOKIN='{"hook_event_name":"pre_tool","tool_name":"bash","tool_input":{"command":"ls /work"}}'
out="$(echo "$HOOKIN" | docker run -i "${hardened[@]}" "${MNT[@]}" "$IMAGE" /opt/glove/vibe-hook 2>/dev/null)"
echo "$out" | grep -q 'nono wrap .* -- bash -lc' && ok "hook rewrites bash command" || bad "hook did not rewrite: $out"
echo "$out" | grep -q 'tool_input' && ok "hook returns tool_input replacement" || bad "no tool_input in hook output"

echo "== baked vibe-hook denies a web-egress tool =="
WEBIN='{"hook_event_name":"pre_tool","tool_name":"web_fetch","tool_input":{"url":"http://x"}}'
echo "$WEBIN" | docker run -i "${hardened[@]}" "${MNT[@]}" "$IMAGE" /opt/glove/vibe-hook 2>/dev/null \
  | grep -q '"deny"' && ok "web_fetch denied" || bad "web_fetch not denied"

echo "== baked vibe-hook fails closed on bad input =="
echo "not json" | docker run -i "${hardened[@]}" "${MNT[@]}" "$IMAGE" /opt/glove/vibe-hook >/dev/null 2>&1 \
  && bad "hook exited 0 on bad input" || ok "hook exits non-zero on bad input (strict -> deny)"

echo "== entrypoint validates policies =="
docker run --rm -v "$POLDIR:/etc/glove/enforcer:ro" --entrypoint /opt/glove/entrypoint.sh "$IMAGE" true >/dev/null 2>&1 \
  && ok "entrypoint execs with valid policies" || bad "entrypoint rejected valid policies"

rm -rf "$WORKDIR" "$HOMEDIR" "$GLOVE_HOME"
echo
echo "== RESULT: $PASS passed, $FAIL failed =="
echo "Manual (need a live LLM): run 'vibe -p ...'; the pre_tool hook fires and a"
echo "prompt-injected bash command runs sandboxed; a hook denial shows in the TUI."
[ "$FAIL" -eq 0 ]
