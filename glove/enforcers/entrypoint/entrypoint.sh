#!/usr/bin/env bash
# glove harness entrypoint (PLAN §4.2).
#
# Validates the ring-1 enforcer policies (if present), then execs the compose
# `command` — which for enforcer=nono is `nono run --profile harness.json -- <TUI>`
# and for enforcer=none is the bare TUI. Fail-closed: if policies exist but are
# invalid, refuse to start: a broken policy must never downgrade to no sandbox,
# and nothing (no env var, no session setting) overrides that.
set -euo pipefail

ENF_DIR=/etc/glove/enforcer

refuse() {
  echo "glove: $1" >&2
  echo "glove: refusing to start without a valid sandbox" >&2
  exit 90
}

if [ -d "$ENF_DIR" ] && command -v nono >/dev/null 2>&1; then
  for p in harness.json tool.json; do
    if [ -f "$ENF_DIR/$p" ]; then
      nono profile validate "$ENF_DIR/$p" >/dev/null 2>&1 || refuse "enforcer policy $p failed validation"
    fi
  done
  # Best-effort readiness check; never fatal (setup is for host installs).
  nono setup --check-only >/dev/null 2>&1 || true
fi

# The tool wrapper starts with glove-pty: without it every command would fail,
# so say why up front.
if [ -f "$ENF_DIR/tool-wrapper.json" ] && grep -q '/opt/glove/bin/glove-pty' "$ENF_DIR/tool-wrapper.json" \
    && [ ! -x /opt/glove/bin/glove-pty ]; then
  refuse "/opt/glove/bin/glove-pty is missing from this image (rebuild it: glove build <harness> --rebuild)"
fi

# srt / nono+srt: srt falls back to its stock apply-seccomp (or none) when the
# configured one is missing, so check glove's srt layer is really there.
for p in srt-settings.json srt-harness.json; do
  if [ -f "$ENF_DIR/$p" ]; then
    for b in /opt/glove/srt/apply-seccomp /opt/glove/bin/glove-pty /opt/glove/srt/node; do
      if [ ! -x "$b" ] || ! grep -q '"applyPath": "/opt/glove/srt/apply-seccomp"' "$ENF_DIR/$p" \
          || ! command -v srt >/dev/null 2>&1; then
        refuse "the srt layer is incomplete ($b, srt, or applyPath in $p)"
      fi
    done
  fi
done

exec "$@"
