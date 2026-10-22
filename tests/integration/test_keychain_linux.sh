#!/usr/bin/env bash
# `keychain:` on Linux (round 23, phase B): glove's Secret Service backend
# (`secret-tool`) against a real gnome-keyring, in a throwaway Ubuntu container
# with a private D-Bus session and an unlocked login keyring; then the same
# code with no D-Bus session (a server, SSH), which must refuse.
#
# A stand-in for an Ubuntu desktop, not one: there the keyring is unlocked at
# login, and a locked one may prompt. Run on a real desktop before calling the
# backend tested (TODO R23.V1).
#
# Usage:  RT=docker|podman bash tests/integration/test_keychain_linux.sh
# Requires: the runtime and network for the image's apt/pip installs.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RT="${RT:-docker}"
IMG="${IMG:-ubuntu:24.04}"

exec "$RT" run --rm -v "$ROOT:/src:ro" -e PYTHONPATH=/src -e PYTHONDONTWRITEBYTECODE=1 -w /tmp "$IMG" bash -c '
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends python3 python3-pip libsecret-tools gnome-keyring dbus \
    >/dev/null
pip3 install -q --break-system-packages typer jinja2 pyyaml rich tomli-w 2>&1 | grep -v "running pip as" || true
echo "== no D-Bus session"
a=0; python3 /src/tests/integration/keychain_linux.py headless || a=$?
echo "== a D-Bus session, an unlocked gnome-keyring"
b=0; dbus-run-session -- bash -c "
  printf glove-it | gnome-keyring-daemon --unlock --components=secrets >/dev/null
  python3 /src/tests/integration/keychain_linux.py desktop
" || b=$?
[ "$a" = 0 ] && [ "$b" = 0 ] && echo "ALL PASS" || { echo "FAILURES"; exit 1; }
'
