"""A private CA bundle a session trusts: `corporate_ca` (the harness) and
`playwright.ca` (the browser sidecar) share one validation, so neither can bind
something the other would refuse."""

from __future__ import annotations

import os
from pathlib import Path

from .config import ConfigError

PEM_CERT = b"-----BEGIN CERTIFICATE-----"
# Any PEM private key (PKCS#8, RSA, EC, encrypted, OpenSSH): a CA bundle is
# public, and whatever is bound is readable by the agent.
PEM_KEY = b"PRIVATE KEY-----"


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
    try:
        pem = host.read_bytes()
    except OSError as e:
        raise ConfigError(f"{label}: cannot read {host}: {e}") from e
    if PEM_KEY in pem:
        raise ConfigError(f"{label}: {host} holds a private key; give a certificate-only bundle")
    if PEM_CERT not in pem:
        raise ConfigError(f"{label}: {host} holds no PEM certificate ({PEM_CERT.decode()})")
    return host
