# glove/vibe — Mistral Vibe inside the sandbox.
# Tools install to SYSTEM paths, never /home/agent: that home is a per-session
# bind mount at runtime and would shadow anything baked into it.
FROM python:3.12-slim

# Ring-1 enforcer: pinned nono binary. Keep in sync with
# glove/enforcers/nono/version.py (`glove build` / tests warn on drift).
COPY --from=ghcr.io/nolabs-ai/nono:0.75.0 /usr/bin/nono /usr/bin/nono

ENV DEBIAN_FRONTEND=noninteractive

# Base + media-analysis toolchain so the sandboxed agent can inspect the
# images/audio/video it collects (webp/png/jpeg, mp4, mp3, metadata) entirely
# in-box — the sandbox has no egress, so analysis must be local.
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates curl \
      ffmpeg imagemagick webp libimage-exiftool-perl \
    && rm -rf /var/lib/apt/lists/*

# uv, used to install vibe + Python runtime libs into system locations.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
ENV UV_TOOL_DIR=/opt/uv/tools \
    UV_TOOL_BIN_DIR=/usr/local/bin \
    UV_PYTHON_INSTALL_DIR=/opt/uv/python

RUN uv tool install mistral-vibe

# Runtime libs the agent's python3 uses: Pillow (PIL) for image analysis — its
# manylinux wheel bundles libjpeg/libwebp so webp/jpeg work out of the box — and
# the v1 `mcp` SDK for the SearXNG stdio server (v2 renamed FastMCP).
RUN uv pip install --system "mcp<2" Pillow

# Optional extra packages from glove.yaml (apt_packages / pip_packages),
# injected as build args so the image stays reproducible per session.
ARG GLOVE_APT=""
ARG GLOVE_PIP=""
RUN if [ -n "$GLOVE_APT" ]; then apt-get update \
      && apt-get install -y --no-install-recommends $GLOVE_APT \
      && rm -rf /var/lib/apt/lists/*; fi
RUN if [ -n "$GLOVE_PIP" ]; then uv pip install --system $GLOVE_PIP; fi

COPY searxng_mcp.py /opt/glove/searxng_mcp.py

# Ring-1 tool hook: rewrites every `bash` tool call to run under the enforcer's
# per-command sandbox (declared in ~/.vibe/hooks.toml by glove). Baked as an
# executable so hooks.toml can invoke it directly.
COPY vibe_hook.py /opt/glove/vibe-hook
COPY entrypoint.sh /opt/glove/entrypoint.sh
RUN chmod 0755 /opt/glove/vibe-hook /opt/glove/entrypoint.sh

# Baked home is overlaid by the per-session bind mount; keep it world-writable
# so an arbitrary runtime uid can use it if the mount is ever absent.
RUN mkdir -p /home/agent && chmod 0777 /home/agent
ENV HOME=/home/agent
WORKDIR /work

# The entrypoint validates the enforcer policies then execs glove's compose
# `command` (for nono: `nono run --profile harness.json -- vibe …`; else bare vibe).
ENTRYPOINT ["/opt/glove/entrypoint.sh"]
