"""Pinned nono release. `glove build` fails loudly on drift."""

from __future__ import annotations

# The nono container image whose /usr/bin/nono is COPY --from'd into harness
# images. Pin both the human-readable tag and the digest that tag resolved to
# when this pin was set (2026-09-03), so a re-tag upstream is caught.
NONO_IMAGE = "ghcr.io/nolabs-ai/nono"
NONO_TAG = "0.75.0"
NONO_DIGEST = "sha256:9f48242999254af75fefe85f17dba500ddde8411260f483ad66bdf8e2d0e8fb4"


def nono_image_ref() -> str:
    """`ghcr.io/nolabs-ai/nono:0.75.0` — the ref used in `COPY --from`."""
    return f"{NONO_IMAGE}:{NONO_TAG}"


def nono_image_pinned() -> str:
    """Fully pinned `image@sha256:…` ref for drift-proof builds."""
    return f"{NONO_IMAGE}:{NONO_TAG}@{NONO_DIGEST}"
