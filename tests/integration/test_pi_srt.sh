#!/usr/bin/env bash
# Phase 4 integration checks (PLAN §8) — the opt-in srt enforcer inside the real
# `glove/pi:0.3.0-srt` image. Reproduces the research §5 matrix and runs the
# tool-command checks: srt wraps tool commands only, under the surgically
# relaxed nested-userns seccomp. See NOTE in test_pi_nono.sh re: pipefail.
#
# Usage:  bash tests/integration/test_pi_srt.sh
# Requires: docker + `glove build pi --enforcer srt`.
set -u

IMAGE="${GLOVE_PI_SRT_IMAGE:-glove/pi:0.3.0-srt}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SECCOMP="$ROOT/glove/runtimes/seccomp/nested-userns.json"
WORKDIR="$(mktemp -d)"; HOMEDIR="$(mktemp -d)"; GLOVE_HOME="$(mktemp -d)"
export GLOVE_HOME
PASS=0 FAIL=0
mkdir -p "$HOMEDIR/.pi/agent"

ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

echo "== rendering srt policies (enforcer: srt) =="
( cd "$WORKDIR" && uv run --project "$ROOT" glove init pi >/dev/null )
printf 'harness: pi\nname: %s\nenforcer: srt\n' "$(basename "$WORKDIR")" > "$GLOVE_HOME/envs/$(basename "$WORKDIR")/glove.yaml"
( cd "$WORKDIR" && uv run --project "$ROOT" glove policy show pi >/dev/null 2>&1 )
# render policies to disk via a dry-run
( cd "$WORKDIR" && uv run --project "$ROOT" glove pi --dry-run >/dev/null 2>&1 )
ENVID="$(basename "$WORKDIR")"
POLDIR="$GLOVE_HOME/envs/$ENVID/sessions/$ENVID/enforcer"
ls "$POLDIR/srt-settings.json" >/dev/null 2>&1 && ok "srt-settings.json rendered" || { bad "no srt settings"; exit 1; }

# weak-mode hardened run (relaxed seccomp, no systempaths), srt wraps tool cmds.
hardened=(--rm --security-opt seccomp="$SECCOMP" --security-opt no-new-privileges:true
          --cap-drop ALL --user 1000:1000 -w /work
          -v "$WORKDIR:/work" -v "$HOMEDIR:/home/agent"
          -e HOME=/home/agent -e GLOVE_LLM_API_KEY=sk-INTEGRATION-SECRET
          -v "$POLDIR:/etc/glove/enforcer:ro")
run_tool() { docker run "${hardened[@]}" "$IMAGE" \
  srt -s /etc/glove/enforcer/srt-settings.json -- bash -lc "$1" 2>&1; }

echo "== srt tool policy (weak mode, surgical seccomp) =="
run_tool 'echo hi > /work/f && cat /work/f' | grep -q '^hi$' && ok "write /work" || bad "write /work"
run_tool 'echo x > /home/agent/.pi/agent/pwn 2>&1; echo rc=$?' | grep -q 'rc=[^0]' \
  && ok "write outside allowWrite -> denied" || bad "wrote outside allowWrite"
run_tool 'curl -sS -m 5 https://example.com >/dev/null 2>&1; echo rc=$?' | grep -q 'rc=[^0]' \
  && ok "network blocked (empty allowedDomains)" || bad "network not blocked"

echo "== srt denyRead hides the harness home =="
docker run "${hardened[@]}" "$IMAGE" bash -lc \
  'echo topsecret > /home/agent/.pi/agent/t && srt -s /etc/glove/enforcer/srt-settings.json -- bash -lc "cat /home/agent/.pi/agent/t 2>&1; echo rc=\$?"' \
  2>&1 | grep -Eq 'No such file|Permission denied|rc=[^0]' && ok "denyRead hides transcript" || bad "transcript readable"

echo "== research matrix: strong mode needs systempaths=unconfined =="
sed 's/"enableWeakerNestedSandbox": true/"enableWeakerNestedSandbox": false/' "$POLDIR/srt-settings.json" > "$WORKDIR/strong.json"
docker run --rm --security-opt seccomp="$SECCOMP" --cap-drop ALL --user 1000:1000 -w /work \
  -v "$WORKDIR:/work" -v "$HOMEDIR:/home/agent" -e HOME=/home/agent "$IMAGE" \
  srt -s /work/strong.json -- bash -lc 'echo strong' 2>&1 | grep -qi 'proc' \
  && ok "strong without systempaths fails (bwrap proc)" || bad "strong ran without systempaths"
docker run --rm --security-opt seccomp="$SECCOMP" --security-opt systempaths=unconfined --cap-drop ALL --user 1000:1000 -w /work \
  -v "$WORKDIR:/work" -v "$HOMEDIR:/home/agent" -e HOME=/home/agent "$IMAGE" \
  srt -s /work/strong.json -- bash -lc 'echo strong_ok' 2>&1 | grep -q 'strong_ok' \
  && ok "strong with systempaths=unconfined works" || bad "strong failed with systempaths"

rm -rf "$WORKDIR" "$HOMEDIR" "$GLOVE_HOME"
echo
echo "== RESULT: $PASS passed, $FAIL failed =="
echo "Documented gaps (see 'glove policy show'): harness process is unwrapped (ring 0 only);"
echo "LLM key stays in the harness env; runs under the relaxed nested-userns seccomp."
[ "$FAIL" -eq 0 ]
