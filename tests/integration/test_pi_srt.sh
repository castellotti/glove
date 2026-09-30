#!/usr/bin/env bash
# Phase 4 integration checks (PLAN §8) — the opt-in srt enforcer inside the real
# `glove/pi:0.5.0-srt` image. Reproduces the research §5 matrix and runs the
# tool-command checks: srt wraps tool commands only, under the surgically
# relaxed nested-userns seccomp. See NOTE in test_pi_nono.sh re: pipefail.
#
# Usage:  bash tests/integration/test_pi_srt.sh
# Requires: docker + `glove build pi --enforcer srt` (the -srt-<hash> overlay image).
set -u
RT="${RT:-docker}"   # docker | podman
if [ "$RT" = podman ]; then
  echo "SKIP: glove refuses enforcer srt on the podman runtime (its relaxed seccomp profile can't be"
  echo "      applied through podman's compose provider); srt is docker-only for now."; exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${GLOVE_PI_SRT_IMAGE:-glove/pi:0.5.0$(uv run --quiet --project "$ROOT" python -c 'from glove.enforcers.base import srt_suffix; print(srt_suffix())')}"
SECCOMP="$ROOT/glove/runtimes/seccomp/nested-userns.json"
WORKDIR="$(mktemp -d)"; HOMEDIR="$(mktemp -d)"; GLOVE_HOME="$(mktemp -d)"
export GLOVE_HOME
PASS=0 FAIL=0
mkdir -p "$HOMEDIR/.pi/agent"

ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "== rendering srt policies (enforcer: srt) =="
. "$ROOT/tests/integration/lib_session.sh"
new_session "$GLOVE_HOME/s" pi 'enforcer: srt\n'
uv run --quiet --project "$ROOT" glove policy "$GLOVE_HOME/s" >/dev/null 2>&1
POLDIR="$S_POLICIES"
ls "$POLDIR/srt-settings.json" >/dev/null 2>&1 && ok "srt-settings.json rendered" || { bad "no srt settings"; exit 1; }

# weak-mode hardened run (relaxed seccomp, no systempaths), srt wraps tool cmds.
hardened=(--rm --security-opt seccomp="$SECCOMP" --security-opt no-new-privileges:true
          --cap-drop ALL --user 1000:1000 -w /work
          -v "$WORKDIR:/work" -v "$HOMEDIR:/home/agent"
          -e HOME=/home/agent -e GLOVE_LLM_API_KEY=sk-INTEGRATION-SECRET
          -v "$POLDIR:/etc/glove/enforcer:ro")
run_tool() { "$RT" run "${hardened[@]}" "$IMAGE" \
  srt -s /etc/glove/enforcer/srt-settings.json -- bash -c "$1" 2>&1; }

echo "== srt tool policy (weak mode, surgical seccomp) =="
run_tool 'echo hi > /work/f && cat /work/f' | grep -q '^hi$' && ok "write /work" || bad "write /work"
run_tool 'echo x > /home/agent/.pi/agent/pwn 2>&1; echo rc=$?' | grep -q 'rc=[^0]' \
  && ok "write outside allowWrite -> denied" || bad "wrote outside allowWrite"
run_tool 'curl -sS -m 5 https://example.com >/dev/null 2>&1; echo rc=$?' | grep -q 'rc=[^0]' \
  && ok "network blocked (empty allowedDomains)" || bad "network not blocked"
# glove's apply-seccomp (srt_image/glove-tighten.c): stock srt lets this succeed
run_tool 'unshare -Ur true 2>&1; echo rc=$?' | grep -q 'rc=[^0]' \
  && ok "no user namespace for tool commands (glove's apply-seccomp)" || bad "tool command created a user namespace"

echo "== srt strips the LLM key from tool commands (credentials.envVars deny) =="
grep -q '"GLOVE_LLM_API_KEY"' "$POLDIR/srt-settings.json" && ok "settings deny GLOVE_LLM_API_KEY" || bad "key not in credentials.envVars"
out="$(run_tool 'env')"
echo "$out" | grep -q 'HOME=/home/agent' || bad "env did not run: $out"
echo "$out" | grep -q 'INTEGRATION-SECRET' && bad "tool command sees the LLM key in env" || ok "tool command env lacks the LLM key"

echo "== harness /proc/<pid>/environ from a tool command =="
# A long-lived process holding the key stands in for the harness (same uid,
# same container /proc) — the question is whether srt's /proc hides it.
cat > "$WORKDIR/environ-probe.sh" <<'PROBE'
# count processes whose /proc/<pid>/environ holds the key (ours is unset)
for f in /proc/[0-9]*/environ; do tr '\0' '\n' < "$f" 2>/dev/null; done | grep -c INTEGRATION-SECRET
PROBE
proc_probe() {  # $1 = settings file, rest = extra docker args
  local settings="$1"; shift
  "$RT" run --rm --security-opt seccomp="$SECCOMP" --security-opt no-new-privileges:true \
    --cap-drop ALL --user 1000:1000 -w /work "$@" \
    -v "$WORKDIR:/work" -v "$HOMEDIR:/home/agent" -e HOME=/home/agent \
    -e GLOVE_LLM_API_KEY=sk-INTEGRATION-SECRET -v "$POLDIR:/etc/glove/enforcer:ro" "$IMAGE" \
    bash -c "sleep 30 & sleep 0.5; srt -s $settings -- bash /work/environ-probe.sh" 2>&1 | tail -1
}
weak_leak="$(proc_probe /etc/glove/enforcer/srt-settings.json)"
echo "  weak mode: processes whose environ exposes the key = $weak_leak"
[ "$weak_leak" = "0" ] && ok "weak: harness environ hidden" || bad "weak mode exposes the harness environ on this kernel (use srt.nested: strong)"

"$RT" run "${hardened[@]}" "$IMAGE" bash -lc \
  'echo topsecret > /home/agent/.pi/agent/t && srt -s /etc/glove/enforcer/srt-settings.json -- bash -c "cat /home/agent/.pi/agent/t 2>&1; echo rc=\$?"' \
  2>&1 | grep -Eq 'No such file|Permission denied|rc=[^0]' && ok "denyRead hides transcript" || bad "transcript readable"

echo "== research matrix: strong mode needs systempaths=unconfined =="
sed 's/"enableWeakerNestedSandbox": true/"enableWeakerNestedSandbox": false/' "$POLDIR/srt-settings.json" > "$WORKDIR/strong.json"
"$RT" run --rm --security-opt seccomp="$SECCOMP" --cap-drop ALL --user 1000:1000 -w /work \
  -v "$WORKDIR:/work" -v "$HOMEDIR:/home/agent" -e HOME=/home/agent "$IMAGE" \
  srt -s /work/strong.json -- bash -c 'echo strong' 2>&1 | grep -qi 'proc' \
  && ok "strong without systempaths fails (bwrap proc)" || bad "strong ran without systempaths"
"$RT" run --rm --security-opt seccomp="$SECCOMP" --security-opt systempaths=unconfined --cap-drop ALL --user 1000:1000 -w /work \
  -v "$WORKDIR:/work" -v "$HOMEDIR:/home/agent" -e HOME=/home/agent "$IMAGE" \
  srt -s /work/strong.json -- bash -c 'echo strong_ok' 2>&1 | grep -q 'strong_ok' \
  && ok "strong with systempaths=unconfined works" || bad "strong failed with systempaths"

echo "== strong mode hides the harness /proc/<pid>/environ =="
strong_leak="$(proc_probe /work/strong.json --security-opt systempaths=unconfined)"
echo "  strong mode: processes whose environ exposes the key = $strong_leak"
[ "$strong_leak" = "0" ] && ok "strong: harness environ hidden (PID namespace)" || bad "strong mode exposes harness environ"

rm -rf "$WORKDIR" "$HOMEDIR" "$GLOVE_HOME"
echo
echo "== RESULT: $PASS passed, $FAIL failed =="
echo "Documented gaps (see 'glove policy show'): harness process is unwrapped (ring 0 only);"
echo "LLM key stays in the harness env; runs under the relaxed nested-userns seccomp."
[ "$FAIL" -eq 0 ]
