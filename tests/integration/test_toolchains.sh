#!/usr/bin/env bash
# `toolchains` end to end (docs/planning/toolchain-provisioning-cleanroom.md §11):
# glove renders a session with pinned Node + Python blocks, builds the derived
# image through its own build path, then runs the rendered harness service
# (internal network only, hardened) with `compose run` — every check below runs
# with NO network: the pinned runtimes, the projects' deps, an installed CLI and
# Playwright's baked Chromium must all work offline. A second session checks
# Vibe (no node in its base; its hook keeps the image's python) and the plan-time
# refusals.
#
# Usage:  bash tests/integration/test_toolchains.sh
# Requires: docker (the build downloads Node, uv, Python, npm/PyPI packages and
# Chromium, so the first run takes a few minutes).
set -u
RT="${RT:-docker}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FIX="$ROOT/tests/integration/fixtures/toolchains"
GLOVE_HOME="$(mktemp -d)"
export GLOVE_HOME
# not under GLOVE_HOME: a project there is refused (it would bake glove's home)
SESSIONS="$(mktemp -d)"
PASS=0 FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
. "$ROOT/tests/integration/lib_session.sh"

NODE_V=22.23.3
PY_V=3.11
TC=/opt/glove/toolchains

build() {  # build the session's images exactly as `glove up` does; prints the harness tag
  uv run --quiet --project "$ROOT" python - "$1" <<'EOF'
import sys
from pathlib import Path
from glove.cli import _materialize_plan, _open
from glove.session import ensure_images
sd, _, sid, cfg = _open(Path(sys.argv[1]))
plan, _, _ = _materialize_plan(sd, sid, cfg)
ensure_images(cfg, plan, cfg.provider)
print(plan.image)
EOF
}

# compose run of the rendered harness service: same image, env, hardening,
# mounts and internal-only network; `tool` adds the rendered tool wrapper
# (what the harness prepends to every shell command).
crun() {  # compose's own progress lines (Container/Network …) dropped
  "$RT" compose -p "glove-$S_ID" -f "$S_COMPOSE" run --rm --no-deps -T "glove-$S_ID-harness" "$@" 2>&1 \
    | grep -v -E '^ (Container|Network|Volume) '
}
tool() {
  # the wrapper's argv has no spaces (bash 3.2 on macOS has no mapfile)
  local w
  w="$(uv run --quiet --project "$ROOT" python -c \
    'import json,sys; print(" ".join(json.load(open(sys.argv[1]))["argv"]))' "$S_POLICIES/tool-wrapper.json")"
  # shellcheck disable=SC2086
  crun $w bash -c "$1"
}
cleanup() { "$RT" compose -p "glove-$S_ID" -f "$S_COMPOSE" down -v >/dev/null 2>&1; }

echo "== session 1: pi (default enforcer) + node $NODE_V (npm ci, chromium) + python $PY_V (uv sync) =="
S1="$SESSIONS/s1"
mkdir -p "$S1/projects"
cp -R "$FIX/node-app" "$FIX/py-app" "$S1/projects/"
# the agent's working copies: only the manifests + lockfiles are baked
mkdir -p "$S1/work" && cp -R "$FIX/node-app" "$FIX/py-app" "$S1/work/"
new_session "$S1" pi "toolchains:
  - {lang: node, version: \"$NODE_V\", project: projects/node-app, browsers: [chromium]}
  - {lang: python, version: \"$PY_V\", project: projects/py-app}
" || { bad "glove plan failed"; exit 1; }
ok "glove plan rendered the session"
trap cleanup EXIT
IMAGE="$(build "$S1" | tail -1)"
[ -n "$IMAGE" ] && "$RT" image inspect "$IMAGE" >/dev/null 2>&1 && ok "derived image built: $IMAGE" \
  || { bad "derived image build failed"; exit 1; }
grep -q "/usr/local/bin/node" "$S_COMPOSE" && ok "pi entry runs on the image's node" || bad "pi entry not pinned"

out="$(crun bash -c 'curl -sS -m 5 https://registry.npmjs.org/ >/dev/null 2>&1; echo rc=$?')"
echo "$out" | grep -q 'rc=[^0]' && ok "runtime has no egress (container level)" || bad "runtime reached the internet: $out"

out="$(tool 'node --version; command -v node')"
echo "$out" | grep -q "^v$NODE_V\$" && echo "$out" | grep -q "^$TC/node/$NODE_V/bin/node\$" \
  && ok "tool: node is the pinned v$NODE_V" || bad "tool: node: $out"
out="$(crun bash -c '/usr/local/bin/node --version; /usr/local/bin/node /usr/local/bin/pi --version >/dev/null 2>&1 && echo pi-ok')"
echo "$out" | grep -q '^v24\.' && echo "$out" | grep -q pi-ok && ok "harness: pi still starts on the image's node 24" \
  || bad "harness: $out"
out="$(tool 'tsc --version')"
echo "$out" | grep -q 'Version 7.0.2' && ok "tool: tsc (project devDependency CLI) runs: $out" || bad "tool: tsc: $out"
# nono's tool profile stops Chromium (denied /proc/self/maps, /proc/sys, /etc/fonts):
# here the engine is checked at container level (same image, env, hardening, no
# network); session 3 runs it inside a shell command under `enforcer: srt`.
out="$(crun bash -c "ls $TC/node/project $TC/python/project")"
echo "$out" | grep -q check && bad "project source was baked: $out" \
  || ok "only manifests + lockfiles baked: $(echo $out)"
out="$(crun bash -c "cd /work/node-app && node check.js")"
echo "$out" | grep -q 'is-number=true title=glove-offline' \
  && ok "container: deps resolve + baked Chromium launches offline (no download)" || bad "container: check.js: $out"
out="$(tool "cd /work && node -e 'console.log(require(\"is-number\")(1))'")"
echo "$out" | grep -q '^true$' && ok "tool: project deps resolve" || bad "tool: require: $out"
out="$(tool "mkdir -p /work/app && cd /work/app && ln -sfn $TC/node/project/node_modules node_modules \
  && echo 'console.log(require(\"./node_modules/is-number\")(2))' > m.js && node m.js")"
echo "$out" | grep -q '^true$' && ok "tool: workspace-shadow strategy (symlink) works from /work" \
  || bad "tool: from /work: $out"
out="$(tool "cd /work/node-app && node check.js")"
echo "$out" | grep -q 'glove-offline' && bad "tool: Chromium unexpectedly starts under nono (update the docs)" \
  || ok "tool: Chromium refused under nono's tool sandbox (documented)"
out="$(tool 'npm install --no-audit left-pad 2>&1; echo rc=$?')"
echo "$out" | tail -1 | grep -q 'rc=[^0]' && ok "tool: a runtime npm install fails (no network)" || bad "tool: npm install worked"

out="$(tool "python --version; cd /work/py-app && python check.py; cd /work && python -c 'import rich; print(\"rich-from-work\")'")"
echo "$out" | grep -q "^Python $PY_V\." && echo "$out" | grep -q "prefix=$TC/python/venv" \
  && echo "$out" | grep -q rich-from-work && ok "tool: python $PY_V venv + project deps (from /work too)" \
  || bad "tool: python: $out"
out="$(tool 'command -v pip; pip --version')"
echo "$out" | head -1 | grep -qx "$TC/python/venv/bin/pip" && echo "$out" | grep -q "python/venv" \
  && ok "tool: pip is the uv-sync venv's own" || bad "tool: pip: $out"
out="$(tool 'pip install --no-cache-dir six 2>&1; echo rc=$?')"
echo "$out" | tail -1 | grep -q 'rc=[^0]' && ok "tool: a runtime pip install fails" || bad "tool: pip install worked"
cleanup

echo "== session 2: vibe + python $PY_V (packages only) + node $NODE_V (no project) =="
S2="$SESSIONS/s2"
new_session "$S2" vibe "toolchains:
  - {lang: python, version: \"$PY_V\", packages: [\"rich==15.0.0\"]}
  - {lang: node, version: \"$NODE_V\", packages: [\"is-number@7.0.0\"]}
" || { bad "glove plan (vibe) failed"; exit 1; }
IMAGE="$(build "$S2" | tail -1)"
[ -n "$IMAGE" ] && ok "derived image built: $IMAGE" || bad "vibe build failed"
grep -q '/usr/local/bin/python3 /opt/glove/vibe-hook' "$S2/.glove/home/.vibe/hooks.toml" \
  && ok "vibe hook runs on the image's python" || bad "vibe hook not pinned"
out="$(crun bash -c 'python3 --version; /usr/local/bin/python3 --version; vibe --version >/dev/null 2>&1 && echo vibe-ok; echo "{}" | /usr/local/bin/python3 /opt/glove/vibe-hook >/dev/null 2>&1; echo hook-rc=$?')"
echo "$out" | grep -q "^Python $PY_V\." && echo "$out" | grep -q '^Python 3\.12\.' && echo "$out" | grep -q vibe-ok \
  && ok "vibe: pinned python on PATH, vibe + its hook keep 3.12 ($(echo "$out" | grep hook-rc))" || bad "vibe: $out"
out="$(tool 'node --version; python -c "import rich; print(\"rich-ok\")"')"
echo "$out" | grep -q "^v$NODE_V\$" && echo "$out" | grep -q rich-ok && ok "tool: node + python packages offline on vibe" \
  || bad "tool (vibe): $out"
cleanup
trap - EXIT

echo "== session 3: pi + enforcer: srt — the baked Chromium inside a shell command =="
S3="$SESSIONS/s3"
mkdir -p "$S3/projects"
cp -R "$FIX/node-app" "$S3/projects/"
mkdir -p "$S3/work" && cp -R "$FIX/node-app" "$S3/work/"
new_session "$S3" pi "enforcer: srt
toolchains:
  - {lang: node, version: \"$NODE_V\", project: projects/node-app, browsers: [chromium]}
" || { bad "glove plan (srt) failed"; exit 1; }
trap cleanup EXIT
IMAGE="$(build "$S3" | tail -1)"
[ -n "$IMAGE" ] && ok "derived image built: $IMAGE" || bad "srt build failed"
# srt points TMPDIR at /tmp/claude without creating it
out="$(tool "mkdir -p \"\$TMPDIR\" && cd /work/node-app && node check.js")"
echo "$out" | grep -q 'is-number=true title=glove-offline' && ok "tool (srt): baked Chromium launches offline" \
  || bad "tool (srt): check.js: $out"
cleanup
trap - EXIT

echo "== plan-time refusals (glove check) =="
refuse() {  # <name> <toolchains yaml> <expected message>
  local d="$SESSIONS/bad-$1"
  mkdir -p "$d/work" "$d/projects/nolock"
  echo '{"name":"x"}' > "$d/projects/nolock/package.json"
  echo x > "$d/projects/file"
  printf 'glove: 3\ntemplate: test\nharness: pi\nextensions:\n  llm: {provider: llama.cpp, location: host, endpoint: "127.0.0.1:8080", model: test-model}\ntoolchains:\n%b' "$2" > "$d/glove-session.yml"
  out="$(COLUMNS=400 uv run --quiet --project "$ROOT" glove check "$d" 2>&1)"; rc=$?
  [ $rc -ne 0 ] && echo "$out" | grep -q "$3" && ok "refused: $1" || bad "$1 not refused (rc=$rc): $out"
}
refuse missing-lockfile '  - {lang: node, version: "22.23.3", project: projects/nolock}\n' 'needs package-lock.json'
refuse not-a-dir '  - {lang: node, version: "22.23.3", project: projects/file}\n' 'is not a directory'
refuse unknown-lang '  - {lang: ruby, version: "3.3.0"}\n' '`lang` must be one of'
refuse no-version '  - {lang: python}\n' '`version` is required'

echo
echo "toolchains: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
