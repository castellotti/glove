"""`python3 -m kstore` entry point."""

from __future__ import annotations

import sys

from .cli import main

raise SystemExit(main(sys.argv[1:]))
