#!/usr/bin/env bash
# Phase 3 integration checks (PLAN §8) — nono enforcer + hook inside the real
# Vibe image. Confirms (1) the shipping glove/vibe base image enforces the same
# ring-1 policies as Pi, and (2) the baked /opt/glove/vibe-hook rewrites bash
# tool calls through the per-command wrapper (what Vibe's pre_tool hook invokes).
# The full LLM/TUI path (hook firing live, strict denial in the TUI) is manual.
#
# Usage:  bash tests/integration/test_vibe_nono.sh
# See NOTE in test_pi_nono.sh about `pipefail` and grep closing pipes.
set -u
RT="${RT:-docker}"   # docker | podman

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/tests/integration/lib_session.sh"
image_driver
IMAGE="${GLOVE_VIBE_IMAGE:-$(ensure_image vibe)}" || exit 1
PASS=0 FAIL=0
mkdir -p "$HOMEDIR/.vibe"

hardened=(--rm --cap-drop ALL --security-opt no-new-privileges:true --user 1000:1000
          --read-only --tmpfs /tmp -w /work
          # nono's state roots on tmpfs, exactly as glove renders them
          # (NonoEnforcer.extra_tmpfs); nono ≥0.78 refuses a state dir it
          # doesn't own, which a reused Docker Desktop bind mount reports as 0.
          --tmpfs /home/agent/.nono:mode=1777 --tmpfs /home/agent/.local/state/nono:mode=1777 -v "$WORKDIR:/work" -v "$HOMEDIR:/home/agent"
          -e HOME=/home/agent -e GLOVE_LLM_API_KEY=sk-INTEGRATION-SECRET)

ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "== rendering glove policies (glove plan) =="
. "$ROOT/tests/integration/lib_session.sh"
new_session "$GLOVE_HOME/s" vibe 'enforcer: nono\n'
POLDIR="$S_POLICIES"
ls "$POLDIR"/*.json >/dev/null 2>&1 && ok "policies rendered" || { bad "no policies"; exit 1; }
MNT=(-v "$POLDIR:/etc/glove/enforcer:ro")
run_tool() { "$RT" run "${hardened[@]}" "${MNT[@]}" "$IMAGE" \
  nono wrap -s --allow-cwd --profile /etc/glove/enforcer/tool.json -- bash -c "$1" 2>&1; }

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
out="$(echo "$HOOKIN" | "$RT" run -i "${hardened[@]}" "${MNT[@]}" "$IMAGE" /opt/glove/vibe-hook 2>/dev/null)"
echo "$out" | grep -q 'nono wrap .* -- bash -c' && ok "hook rewrites bash command" || bad "hook did not rewrite: $out"
echo "$out" | grep -q 'tool_input' && ok "hook returns tool_input replacement" || bad "no tool_input in hook output"

echo "== baked vibe-hook denies a web-egress tool =="
WEBIN='{"hook_event_name":"pre_tool","tool_name":"web_fetch","tool_input":{"url":"http://x"}}'
echo "$WEBIN" | "$RT" run -i "${hardened[@]}" "${MNT[@]}" "$IMAGE" /opt/glove/vibe-hook 2>/dev/null \
  | grep -q '"deny"' && ok "web_fetch denied" || bad "web_fetch not denied"

echo "== baked vibe-hook fails closed on bad input =="
echo "not json" | "$RT" run -i "${hardened[@]}" "${MNT[@]}" "$IMAGE" /opt/glove/vibe-hook >/dev/null 2>&1 \
  && bad "hook exited 0 on bad input" || ok "hook exits non-zero on bad input (strict -> deny)"

echo "== entrypoint validates policies =="
"$RT" run "${hardened[@]}" -v "$POLDIR:/etc/glove/enforcer:ro" --entrypoint /opt/glove/entrypoint.sh "$IMAGE" true >/dev/null 2>&1 \
  && ok "entrypoint execs with valid policies" || bad "entrypoint rejected valid policies"

echo "== tool commands have no controlling terminal (no TIOCSTI into the harness) =="
# a harness-like process on a real tty runs the rendered wrapper; the command
# tries to open /dev/tty. Baseline: the same command unwrapped opens it.
TTYCMD='perl -e '"'"'open(T, "+<", "/dev/tty") or die "TTY-REFUSED: $!\n"; print "TTY-OPENED\n"'"'"
WRAP="$(uv run --quiet --no-project python -c 'import json,shlex,sys; print(shlex.join(json.load(open(sys.argv[1]))["argv"]))' "$POLDIR/tool-wrapper.json")"
tty_run() { uv run --quiet --no-project python "$ROOT/tests/integration/in_pty.py" "$RT" run -it "${hardened[@]}" "${MNT[@]}" \
  --entrypoint bash "$IMAGE" -c "$1" 2>&1; }
tty_run "$TTYCMD" | grep -q 'TTY-OPENED' && ok "baseline: an unwrapped command opens /dev/tty" \
  || bad "baseline could not open /dev/tty (the check cannot detect the gap)"
# as a child of the harness (what Pi and Vibe do), and as the session leader
for how in "a child of the harness" "the session leader"; do
  shape="$WRAP bash -c $(printf %q "$TTYCMD")"; [ "$how" = "a child of the harness" ] && shape="$shape; true"
  out="$(tty_run "$shape")"
  echo "$out" | grep -q 'TTY-REFUSED: No such device' && ! echo "$out" | grep -q 'TTY-OPENED' \
    && ok "wrapped command cannot open /dev/tty (wrapper as $how)" \
    || bad "wrapped command opened /dev/tty ($how): $out"
done

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
# `vibe -p` through the stub (the pre_tool hook wraps the command) and a hook
# denial shown in the TUI: test_config_protect.sh vibe.
[ "$FAIL" -eq 0 ]
