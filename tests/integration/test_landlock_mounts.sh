#!/usr/bin/env bash
# Live (landlock mounts round): commands under a nono enforcer use /work on this
# runtime's bind mounts. On Docker Desktop 4.96+ the harness's binds come from
# its virtiofs layer (its fakeowner layer makes Landlock deny every open);
# elsewhere they stay as they are. Either way the same checks pass.
#
#   bash tests/integration/test_landlock_mounts.sh [nono|nono+srt]   # default both
#   RT=podman …
#   MOUNTS=native …   the control on Docker Desktop 4.96: the normal path, where /work fails under nono
#
# A throwaway session (Pi with python3, as the MX-5 research instance; webfetch
# {downloads: work} for a read-only /work/downloads) is rendered by glove, its images built and its sidecars
# started as `glove up` does (mount-watch too: Docker Desktop's virtiofs layer sees host-side changes only
# through it), then the rendered harness service runs with `compose run` (same image,
# env, hardening, binds, internal network only) and every check goes through the
# session's own tool wrapper: what the harness prepends to each shell command.
# No LLM. Uses a throwaway GLOVE_HOME; tears everything down.
set -u
RT="${RT:-docker}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENFORCERS=("${@:-nono}")
[ "$#" -eq 0 ] && ENFORCERS=(nono nono+srt)
. "$ROOT/tests/integration/lib_session.sh"
driver_init
runtime_facts
PASS=0 FAIL=0
ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

build() {  # the session's images and sidecars, as `glove up` builds and starts them
  uv run --quiet --project "$ROOT" python - "$1" <<'EOF'
import sys
from pathlib import Path
from glove.plan import secret_env
from glove.sessionops import materialize_plan, open_session
from glove.session import compose_process_env, ensure_images, start_sidecars
sd, _, sid, cfg = open_session(Path(sys.argv[1]))
plan, _, _ = materialize_plan(sd, sid, cfg)
ensure_images(cfg, plan, cfg.provider)
start_sidecars(plan, sd.compose, provider=cfg.provider, env=compose_process_env(cfg.provider, secret_env(plan)))
EOF
}
crun() {  # compose run of the rendered harness service; compose's progress lines dropped
  "$RT" compose -p "glove-$S_ID" -f "$S_COMPOSE" run --rm --no-deps -T "glove-$S_ID-harness" "$@" 2>&1 \
    | grep -v -E '^ (Container|Network|Volume) '
}
tool() {  # a shell command as the harness runs one: inside the session's tool wrapper
  local w
  w="$(uv run --quiet --project "$ROOT" python -c \
    'import json,shlex,sys; print(shlex.join(json.load(open(sys.argv[1]))["argv"]))' "$S_POLICIES/tool-wrapper.json")"
  eval "crun $w bash -c $(printf %q "$1")"
}
cleanup() { [ -n "${S_COMPOSE:-}" ] && "$RT" compose -p "glove-$S_ID" -f "$S_COMPOSE" down -v >/dev/null 2>&1; }
ON_EXIT=cleanup
# MOUNTS=native|virtiofs: `docker_desktop_mounts:` (MOUNTS=native on Docker Desktop 4.96 is the control: /work fails)
if [ -n "${MOUNTS:-}" ]; then mkdir -p "$GLOVE_HOME"; echo "docker_desktop_mounts: $MOUNTS" > "$GLOVE_HOME/config.yml"; fi

uv run --quiet --project "$ROOT" glove doctor --runtime "$RT" --enforcer nono 2>/dev/null \
  | grep 'landlock on a bind mount' \
  || echo "  (doctor printed no 'landlock on a bind mount' line)"

for enf in "${ENFORCERS[@]}"; do
  if [ "${enf#*srt}" != "$enf" ] && [ -n "$SRT_REFUSED" ]; then echo "== $enf: skipped ($SRT_REFUSED)"; continue; fi
  cleanup
  S="$TMPROOT/s-${enf/+/-}"
  echo "== runtime $RT, enforcer $enf"
  new_session "$S" pi "  webfetch: {downloads: work}\n  direct: {}\nenforcer: $enf\napt_packages: [python3]\n" \
    || { bad "$enf: glove plan failed"; continue; }
  build "$S" >/dev/null || { bad "$enf: image build or sidecar start failed"; continue; }
  layer="bind_layer: ${S_LAYER:-native}"
  if grep -q '/run/host_virtiofs' "$S_COMPOSE"; then src=virtiofs; else src=native; fi
  [ "$layer" = "bind_layer: $src" ] && ok "$enf: $layer (compose sources agree)" || bad "$enf: $layer vs compose $src"
  if [ "$src" = virtiofs ]; then
    grep -qF 'safe.directory\u0027=\u0027*\u0027' "$S_COMPOSE" && ok "$enf: safe.directory '*'" || bad "$enf: no safe.directory '*'"
  fi
  echo host-content > "$S/work/host.txt"
  mkdir -p "$S/downloads" && echo dl-content > "$S/downloads/dl.txt"

  out="$(tool 'cat /work/host.txt')"
  [ "$out" = host-content ] && ok "$enf: read a host file in /work" || bad "$enf: read /work: $out"
  out="$(tool 'echo hi > /work/a && mv /work/a /work/b && mkdir -p /work/d/e && echo x > /work/d/e/f && cat /work/b && ls /work/d/e')"
  [ "$out" = "$(printf 'hi\nf')" ] && ok "$enf: create, write, rename, mkdir, list" || bad "$enf: write ops: $out"
  [ "$(cat "$S/work/b" 2>/dev/null)" = hi ] && ok "$enf: the host sees what the command wrote" || bad "$enf: host side"
  out="$(tool 'cat /work/downloads/dl.txt; (echo y > /work/downloads/dl.txt) 2>/dev/null; echo rc=$?')"
  [ "$out" = "$(printf 'dl-content\nrc=1')" ] && ok "$enf: /work/downloads readable, not writable" || bad "$enf: downloads: $out"
  out="$(tool 'cd /work && mkdir -p t && printf "import unittest\nclass T(unittest.TestCase):\n    def test(self): self.assertTrue(True)\n" > t/test_x.py && python3 -m unittest discover -s t 2>&1 | tail -1')"
  [ "$out" = OK ] && ok "$enf: python unittest in /work" || bad "$enf: unittest: $out"
  out="$(tool 'python3 -c "import sqlite3,fcntl,mmap; c=sqlite3.connect(\"/work/db.sqlite\"); c.execute(\"create table t(x)\"); c.execute(\"insert into t values (7)\"); c.commit(); f=open(\"/work/b\",\"r+b\"); fcntl.flock(f,fcntl.LOCK_EX); print(c.execute(\"select x from t\").fetchone()[0], mmap.mmap(f.fileno(),0)[:2].decode())"')"
  [ "$out" = "7 hi" ] && ok "$enf: sqlite, flock, mmap" || bad "$enf: sqlite/flock/mmap: $out"
  # the host replaces (as glove re-renders a policy) and deletes files the harness has already read
  echo v1 > "$S/work/h.txt"; tool 'cat /work/h.txt /work/b' >/dev/null
  python3 -c 'import os, sys, tempfile; fd, t = tempfile.mkstemp(dir=sys.argv[1]); os.write(fd, b"v2\n"); os.close(fd)
os.replace(t, os.path.join(sys.argv[1], "work", "h.txt")); os.unlink(os.path.join(sys.argv[1], "work", "b"))' "$S"
  out="$(tool 'cat /work/h.txt; test -e /work/b && echo b-still-there; true')"
  # podman's virtiofs: a replaced file reads as missing for under 2 s, then right (never stale)
  [ "$out" != v2 ] && [ "$RT" = podman ] && sleep 2 && out="$(tool 'cat /work/h.txt; test -e /work/b && echo b-still-there; true')"
  [ "$out" = v2 ] && ok "$enf: the harness sees the host replace and delete files" || bad "$enf: host changes: $out"
  # a nested repo, checked after a pause: on the raw virtiofs layer a new dir's owner can turn 0:0
  out="$(tool 'cd /work && mkdir -p repo && cd repo && git init -q && echo a > a && git add a && git -c user.name=t -c user.email=t@example.invalid commit -qm one && sleep 2 && git status --short && git log --oneline | wc -l')"
  [ "$(echo "$out" | tr -d ' ')" = 1 ] && ok "$enf: git init/commit/status in /work/repo" || bad "$enf: git: $out"
  # Landlock is on, not bypassed: the harness's config home (rw for the harness) is denied to a command
  out="$(tool 'ls /home/agent/.pi/agent 2>&1')"
  echo "$out" | grep -qi 'permission denied' && ok "$enf: Landlock still denies the harness home" \
    || bad "$enf: harness home readable: $out"
done
echo "== $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
