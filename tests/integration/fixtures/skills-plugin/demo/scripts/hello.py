#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
import sys

print(f"HELLO python={sys.version_info[0]}.{sys.version_info[1]}")
