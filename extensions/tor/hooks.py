"""`tor` extension hooks: the exit check (verify's `exit-confirmed`, the Tor
Project's check through privoxy), from the `exitcheck` library."""

from extensions.exitcheck.exitcheck import verify  # noqa: F401
