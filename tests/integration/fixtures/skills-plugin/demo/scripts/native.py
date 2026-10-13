#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["rpds-py==0.27.1"]
# ///
import rpds

print(f"NATIVE {len(rpds.HashTrieMap({'a': 1}))}")
