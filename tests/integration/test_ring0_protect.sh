#!/usr/bin/env bash
# Ring-0 read-only binds (v3 plan §6.3): the agent cannot plant git hooks or
# rewrite .git/config (both later run/trusted on the HOST), and with
# `protect_ide_files: true` cannot create .envrc/.mcp.json/.vscode.
#
# Renders a real session with `glove pi --dry-run` and runs the rendered
# harness service via `docker compose run`, so the check covers the compose
# file glove actually emits (not a hand-built docker run). Inside, commands run
# under ring 1 (nono wrap, as the Pi enforcer does) AND ring 0; the protected
# paths must hold even for the harness process itself (plain bash, no nono).
#
# Usage:  bash tests/integration/test_ring0_protect.sh
# Requires: docker + `glove build pi`. See NOTE in test_pi_nono.sh re: pipefail.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORKDIR="$(mktemp -d)"; GLOVE_HOME="$(mktemp -d)"
export GLOVE_HOME
PASS=0 FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

git -C "$WORKDIR" init -q && git -C "$WORKDIR" config user.email t@example.com && git -C "$WORKDIR" config user.name t
echo hi > "$WORKDIR/README" && git -C "$WORKDIR" add README && git -C "$WORKDIR" commit -qm init
ENVID="$(basename "$WORKDIR")"

echo "== rendering (glove pi --dry-run, protect_ide_files: true) =="
( cd "$WORKDIR" && uv run --project "$ROOT" glove init pi >/dev/null )
printf 'harness: pi\nname: %s\nprotect_ide_files: true\n' "$ENVID" > "$GLOVE_HOME/envs/$ENVID/glove.yaml"
( cd "$WORKDIR" && uv run --project "$ROOT" glove pi --dry-run >/dev/null 2>&1 )
SDIR="$GLOVE_HOME/envs/$ENVID/sessions/$ENVID"
COMPOSE="$(ls "$SDIR"/*.yml "$SDIR"/*.yaml 2>/dev/null | head -1)"
[ -n "$COMPOSE" ] && ok "compose rendered ($COMPOSE)" || { bad "no compose file in $SDIR"; ls -la "$SDIR"; exit 1; }
grep -q '/work/.git/hooks' "$COMPOSE" && ok "compose has the .git/hooks bind" || bad "no .git/hooks bind"

# A denial must be a real kernel refusal: an enforcer that failed to start
# also exits non-zero, which would otherwise pass as "denied".
denied() { echo "$1" | grep -q 'rc=[^0]' && echo "$1" | grep -Eq 'Read-only file system|Permission denied'; }
run() {  # run $1 inside the rendered harness service, bypassing the TUI
  docker compose -f "$COMPOSE" run --rm --no-deps -T --entrypoint bash "glove-$ENVID-harness" -c "$1" 2>&1
}
TOOL='nono wrap -s --allow-cwd --profile /etc/glove/enforcer/tool.json -- bash -c'

echo "== the agent cannot plant or edit host-trusted files =="
for who in harness tool; do
  if [ "$who" = tool ]; then pre="$TOOL"; else pre="bash -c"; fi
  out="$(run "$pre 'echo evil > /work/.git/hooks/pre-commit; echo rc=\$?'")"
  denied "$out" && ok "$who: write .git/hooks/pre-commit denied" || bad "$who: wrote pre-commit: $out"
  out="$(run "$pre 'echo \"[core] hooksPath=/tmp\" >> /work/.git/config; echo rc=\$?'")"
  denied "$out" && ok "$who: append .git/config denied" || bad "$who: appended .git/config: $out"
  out="$(run "$pre 'echo x > /work/.envrc; echo rc=\$?'")"
  denied "$out" && ok "$who: write .envrc denied" || bad "$who: wrote .envrc: $out"
  out="$(run "$pre 'echo x > /work/.vscode/tasks.json; echo rc=\$?'")"
  denied "$out" && ok "$who: write .vscode/tasks.json denied" || bad "$who: wrote .vscode: $out"
done
[ ! -e "$WORKDIR/.git/hooks/pre-commit" ] && ok "host: no pre-commit hook exists" || bad "host: pre-commit planted"

echo "== normal git work still functions =="
out="$(run "$TOOL 'cd /work && echo more >> README && git -c safe.directory=/work add README && git -c safe.directory=/work -c user.email=a@b -c user.name=a commit -qm two && echo committed'")"
echo "$out" | grep -q committed && ok "git commit from a tool command works" || bad "git commit failed: $out"

echo "== .git cannot be renamed or removed to swap in a fresh one =="
for who in harness tool; do
  if [ "$who" = tool ]; then pre="$TOOL"; else pre="bash -c"; fi
  out="$(run "$pre 'cd /work && mv .git .git-moved; echo rc=\$?'")"
  echo "$out" | grep -q 'rc=[^0]' && ok "$who: mv .git denied ($(echo "$out" | grep -o 'Device or resource busy\|Permission denied' | head -1))" \
    || bad "$who: renamed .git away: $out"
done
[ -d "$WORKDIR/.git" ] && [ ! -e "$WORKDIR/.git-moved" ] && ok "host: .git intact" || bad "host: .git moved"

rm -rf "$WORKDIR" "$GLOVE_HOME" 2>/dev/null || true
echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
