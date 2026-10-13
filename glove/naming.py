"""Names of a session's compose project and everything scoped to it."""

from __future__ import annotations

import re

# A host name, or `*.<domain>` for its subdomains: lower-case DNS labels
# (an extension's host allowlists and filters; fullmatch it).
HOST_GLOB = re.compile(r"(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*")


def project_name(session: str) -> str:
    return f"glove-{session}"


def scoped(session: str, name: str) -> str:
    """A container, network, volume or secret owned by the session's project."""
    return f"{project_name(session)}-{name}"
