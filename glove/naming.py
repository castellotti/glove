"""Names of a session's compose project and everything scoped to it."""

from __future__ import annotations


def project_name(session: str) -> str:
    return f"glove-{session}"


def scoped(session: str, name: str) -> str:
    """A container, network, volume or secret owned by the session's project."""
    return f"{project_name(session)}-{name}"
