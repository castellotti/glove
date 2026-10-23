"""Runs inside test_keychain_linux.sh's Ubuntu container: `keychain:` against a
real Secret Service (gnome-keyring over a private D-Bus session), then with
no D-Bus session at all. Prints PASS/FAIL lines; exits non-zero on a failure."""

from __future__ import annotations

import os
import subprocess
import sys

from extensions.keychain.store import keychain_set
from glove.api import ConfigError, keychain_tool, resolve_secret, secret_exists

FAIL = 0


def check(ok: bool, what: str) -> None:
    global FAIL
    print(("  PASS: " if ok else "  FAIL: ") + what)
    FAIL += not ok


def refused(fn, *args) -> str:
    try:
        fn(*args)
    except ConfigError as e:
        return str(e)
    return ""


def main(mode: str) -> int:
    if mode == "headless":
        os.environ.pop("DBUS_SESSION_BUS_ADDRESS", None)
        why = refused(resolve_secret, "keychain:x")
        check(why.startswith("keychain:x: secret-tool: ") and "env:<VAR>" in why,
              f"no D-Bus session: resolve_secret says why: {why}")
        why = refused(keychain_set, "x", "s3cret")
        check(why.startswith("secret-tool: ") and "env:<VAR>" in why, f"  ... keychain_set too: {why}")
        ok, detail = secret_exists("keychain:x")
        check(not ok and "env:<VAR>" in detail, f"  ... secret_exists says why: {detail}")
        return FAIL
    check(keychain_tool() == "secret-tool", "a D-Bus session with secret-tool: the Secret Service backend")
    ok, detail = secret_exists("keychain:glove-it-missing")
    check(not ok and "glove keychain set glove-it-missing" in detail, f"a missing item: {detail}")
    check("no Secret Service item" in refused(resolve_secret, "keychain:glove-it-missing"),
          "a missing item: resolve_secret refuses")
    for name, value in (("short", "sk-0123"), ("quoted", 'a b"c\\d $x `y`'), ("long", "v" * 20_000),
                        ("unicode", "héllo ✓")):
        rc = keychain_set(f"glove-it-{name}", value)
        check(rc == 0 and resolve_secret(f"keychain:glove-it-{name}") == value,
              f"{name} ({len(value)} chars): stored and read back exactly")
    check(keychain_set("glove-it-short", "sk-new") == 0 and resolve_secret("keychain:glove-it-short") == "sk-new",
          "storing again replaces the value")
    def raw(service: str) -> bytes | None:  # what secret-tool itself holds
        r = subprocess.run(["secret-tool", "lookup", "application", "glove", "service", service], capture_output=True)
        return r.stdout if r.returncode == 0 else None

    # secret-tool keeps the first 8 KB of stdin and exits 0: a long value must be in parts
    parts = [raw(f"glove-it-long.part{i}") for i in range(1, 5)]
    check(raw("glove-it-long").startswith(b"glove-parts:3:") and all(parts[:3]) and parts[3] is None
          and all(len(p) <= 8000 for p in parts[:3]), "the long value: a head and three parts, each under 8 KB")
    check(keychain_set("glove-it-long", "short") == 0 and resolve_secret("keychain:glove-it-long") == "short"
          and raw("glove-it-long.part1") is None, "a short value stored over it clears the parts")
    check(secret_exists("keychain:glove-it-short") == (True, "Secret Service item exists"), "secret_exists: found")
    cli = subprocess.run([sys.executable, "-c", "from glove.cli import main; main()", "keychain", "set", "--stdin",
                          "glove-it-cli"], input="piped-s3cret\n", capture_output=True, text=True)
    shown = cli.stdout + cli.stderr
    check(cli.returncode == 0 and "keychain:glove-it-cli" in shown and "piped-s3cret" not in shown,
          "glove keychain set --stdin (the extension's CLI)")
    check(not refused(resolve_secret, "keychain:glove-it-cli") and resolve_secret("keychain:glove-it-cli")
          == "piped-s3cret", "  ... read back")
    return FAIL


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
