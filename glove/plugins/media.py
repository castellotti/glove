"""``media`` plugin — the image/audio/video analysis toolchain.

The sandbox has no egress, so any media a session collects must be inspected
in-box. This restores the toolchain that used to be baked into every image
(ffmpeg, ImageMagick, libwebp, exiftool, and PIL) as an opt-in layer: enabled
only when a session declares `plugins: [media]`.

Pure image contribution — the tools run as ordinary shell commands under the
ring-1 tool policy (confined to /work + rw mounts + /tmp, no network), so the
plugin needs no network, host-service, mount, or ring-1 grant.
"""

from __future__ import annotations

from .base import ALL_HARNESSES, ImageLayer, Plugin

MEDIA = Plugin(
    name="media",
    summary="image/audio/video analysis toolchain (ffmpeg, imagemagick, webp, exiftool, PIL)",
    image={
        # Shared across Debian-based harness images.
        ALL_HARNESSES: ImageLayer(
            apt=("ffmpeg", "imagemagick", "webp", "libimage-exiftool-perl")
        ),
        # Vibe's base is python:3.12-slim with uv; PIL comes from the Pillow
        # wheel (bundles libjpeg/libwebp).
        "vibe": ImageLayer(pip=("Pillow",)),
        # Pi's base is node-only; add Python + system PIL for image analysis.
        "pi": ImageLayer(apt=("python3", "python3-pil")),
    },
)
