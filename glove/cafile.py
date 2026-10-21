"""Every CA a session trusts goes one way: `corporate_ca` and an extension's
`type: ca` setting are validated here and copied into `.glove/trust/` (bound
read-only at TRUST_DIR); with a read-only channel's `trust` file they make the
one bundle `trust_script` builds at start, on a tmpfs that every enforcer but
`none` keeps the agent from writing."""

from __future__ import annotations

import os
import shlex
from pathlib import Path

from .config import ConfigError

PEM_CERT = b"-----BEGIN CERTIFICATE-----"
# Any PEM private key (PKCS#8, RSA, EC, encrypted, OpenSSH): a CA bundle is
# public, and whatever is bound is readable by the agent.
PEM_KEY = b"PRIVATE KEY-----"

# Under /etc/glove, which every enforcer lets the harness and its commands
# read (nono: GLOVE_READ; srt: the whole rootfs) and none lets them write
# (`enforcer: none` holds nothing: the tmpfs belongs to the session uid).
TRUST_DIR = "/etc/glove/trust"  # .glove/trust/: the validated copies
CORPORATE_CA = "corporate_ca.pem"  # corporate_ca's copy there
CA_DIR = "/etc/glove/ca"  # a tmpfs: what trust_script builds
# The image's roots (every image that trusts is Debian's or Ubuntu's, with
# ca-certificates), then the CAs: for the TLS clients that replace their trust
# store rather than add to it. Node adds the CAs alone (NODE_EXTRA_CA_CERTS).
SYSTEM_ROOTS = "/etc/ssl/certs/ca-certificates.crt"
# Python, curl, git and gh (Go) read the bundle; Node adds the CAs to its own.
TRUST_ENV = {**dict.fromkeys(("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO"),
                             f"{CA_DIR}/bundle.pem"), "NODE_EXTRA_CA_CERTS": f"{CA_DIR}/extra.pem"}
CA_WAIT = 30  # seconds for a channel's CA to appear (its sidecar writes it as it starts)


def trust_script(cas: list[str], dest: str = CA_DIR) -> str:
    """sh that writes `dest`/extra.pem (the `cas`) and `dest`/bundle.pem (the
    image's roots, then the `cas`), waiting up to CA_WAIT seconds for a
    channel's (the copies are there from the start). A CA that is missing, or
    no roots, exits 90 (the entrypoint's refusal): nothing starts trusting
    less than the session says, or nothing at all."""
    q = " ".join(map(shlex.quote, cas))
    wait = " ".join(shlex.quote(c) for c in cas if not c.startswith(f"{TRUST_DIR}/"))
    has = "grep -qF 'BEGIN CERTIFICATE'"
    return ((f'for f in {wait}; do i=0; until {has} "$f" 2>/dev/null || [ $i -ge {CA_WAIT} ]; do i=$((i+1)); '
             'sleep 1; done; done; ' if wait else '') + f'for f in {q}; do {has} "$f" 2>/dev/null || '
            f'{{ echo "glove: the trusted CA $f is missing" >&2; exit 90; }}; done; '
            f'{has} {SYSTEM_ROOTS} || {{ echo "glove: no CA roots at {SYSTEM_ROOTS}" >&2; exit 90; }}; '
            f'for f in {q}; do cat "$f"; echo; done > {dest}/extra.pem && '
            f'cat {SYSTEM_ROOTS} {dest}/extra.pem > {dest}/bundle.pem || exit 90; ')


def trust_argv(cas: list[str], argv: list[str]) -> list[str]:
    """`argv`, run once `trust_script` has built CA_DIR's files."""
    return ["/bin/sh", "-c", trust_script(cas) + 'exec "$@"', "glove-trust", *argv]


def resolve_ca_file(label: str, value: object, session_dir: Path | None) -> Path:
    """`value` as a validated host path (``~`` expanded, relative to the session
    directory, symlinks resolved): a regular file holding at least one PEM
    certificate and no private key, and not the session file or anything in
    the session's private state. Raises ConfigError naming `label`."""
    from .mounts import existing_host_path
    from .sessiondir import SESSION_FILE, STATE_DIR

    if not isinstance(value, str) or not value:
        raise ConfigError(f"{label}: must be a path string, got {value!r}")
    try:
        host = existing_host_path(session_dir, value, "file")
    except ValueError as e:
        raise ConfigError(f"{label}: {e}") from None
    if session_dir is not None:
        root = Path(os.path.realpath(session_dir))
        if host == root / SESSION_FILE or host.is_relative_to(root / STATE_DIR):
            raise ConfigError(f"{label}: {value!r} must not be the session file or inside {STATE_DIR}/")
    read_ca(label, host)
    return host


def read_ca(label: str, host: Path) -> str:
    """`host`'s text, checked: at least one PEM certificate, no private key.
    Called again when it is copied, so a file changed since the plan is never
    bound unchecked."""
    try:
        pem = host.read_bytes()
        text = pem.decode()
    except (OSError, UnicodeDecodeError) as e:
        raise ConfigError(f"{label}: cannot read {host} as text: {e}") from e
    if PEM_KEY in pem:
        raise ConfigError(f"{label}: {host} holds a private key; give a certificate-only bundle")
    if PEM_CERT not in pem:
        raise ConfigError(f"{label}: {host} holds no PEM certificate ({PEM_CERT.decode()})")
    return text
