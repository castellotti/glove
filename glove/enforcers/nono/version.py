"""Pinned nono release. `glove build` fails loudly on drift."""

from __future__ import annotations

# The nono container image whose /usr/bin/nono is COPY --from'd into harness
# images. Pin both the human-readable tag and the (multi-arch index) digest that
# tag resolved to when this pin was set (2026-09-28), so a re-tag upstream is
# caught. 0.78.0 carries five GHSA fixes (packs, tool-sandbox, proxy L7 paths —
# none in the Landlock `run`/`wrap` path glove uses, but bump anyway).
NONO_IMAGE = "ghcr.io/nolabs-ai/nono"
NONO_TAG = "0.78.0"
NONO_DIGEST = "sha256:5a213ddc296761a7ad9b6fbcb14ac0e9660f33c23b0b4eb70ea7c933231ca079"


def nono_image_ref() -> str:
    """Fully pinned `image:tag@sha256:…` — the ref used in `COPY --from`."""
    return f"{NONO_IMAGE}:{NONO_TAG}@{NONO_DIGEST}"
