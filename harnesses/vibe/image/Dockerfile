# glove/vibe — Mistral Vibe inside the sandbox.
# Tools install to SYSTEM paths, never /home/agent: that home is a per-session
# bind mount at runtime and would shadow anything baked into it.
# glove-pty (glove/enforcers/pty, passed as the `glovepty` build context): tool
# commands start with `glove-pty notty` so they cannot type into this TUI (TIOCSTI).
FROM debian:bookworm-slim AS glove-pty
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY --from=glovepty glove-pty.c /src/
RUN gcc -static -O2 -Wall -Wextra -o /src/glove-pty /src/glove-pty.c -lutil && strip /src/glove-pty

FROM python:3.12-slim

# Ring-1 enforcer: pinned nono binary. Keep in sync with
# glove/enforcers/nono/version.py (`glove build` / tests warn on drift).
COPY --from=ghcr.io/nolabs-ai/nono:0.78.0@sha256:5a213ddc296761a7ad9b6fbcb14ac0e9660f33c23b0b4eb70ea7c933231ca079 /usr/bin/nono /usr/bin/nono

ENV DEBIAN_FRONTEND=noninteractive

# Minimal base: just what Vibe + the enforcer need. Optional capabilities
# (search client, browser, media toolchain) are opt-in plugins composed into a
# per-session image variant when enabled — never baked into this base.
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# uv, used to install vibe + Python runtime libs into system locations.
COPY --from=ghcr.io/astral-sh/uv:0.12.23@sha256:61d393e44e249f2e4b526b6c7ddcecce245946826e608e11c93ad4f5bba55b21 /uv /usr/local/bin/uv
ENV UV_TOOL_DIR=/opt/uv/tools \
    UV_TOOL_BIN_DIR=/usr/local/bin \
    UV_PYTHON_INSTALL_DIR=/opt/uv/python

# The pinned Vibe release: harness.yml's `version`, passed by glove as a build arg.
# Its dependencies are pinned by vibe-constraints.txt (mistral-vibe itself only
# gives ranges). To bump, regenerate it with the new version:
#   echo mistral-vibe==<v> | uv pip compile --universal --python-version 3.12 --no-header - -o vibe-constraints.txt
ARG HARNESS_VERSION
COPY vibe-constraints.txt /tmp/vibe-constraints.txt
RUN : "${HARNESS_VERSION:?glove passes harness.yml's version}" \
    && grep -qx "mistral-vibe==${HARNESS_VERSION}" /tmp/vibe-constraints.txt \
    && uv tool install --python 3.12 --no-cache --constraints /tmp/vibe-constraints.txt "mistral-vibe==${HARNESS_VERSION}" \
    && rm /tmp/vibe-constraints.txt

# Optional extra packages from glove.yaml (apt_packages / pip_packages),
# injected as build args so the image stays reproducible per session.
ARG GLOVE_APT=""
ARG GLOVE_PIP=""
RUN if [ -n "$GLOVE_APT" ]; then apt-get update \
      && apt-get install -y --no-install-recommends $GLOVE_APT \
      && rm -rf /var/lib/apt/lists/*; fi
RUN if [ -n "$GLOVE_PIP" ]; then uv pip install --system $GLOVE_PIP; fi

# Ring-1 tool hook: rewrites every `bash` tool call to run under the enforcer's
# per-command sandbox (declared in ~/.vibe/hooks.toml by glove). Baked as an
# executable so hooks.toml can invoke it directly.
COPY --chmod=0755 vibe_hook.py /opt/glove/vibe-hook
COPY --from=glove-pty /src/glove-pty /opt/glove/bin/glove-pty
# The shared entrypoint (glove/enforcers/entrypoint, the `gloveentry` build context).
COPY --chmod=0755 --from=gloveentry entrypoint.sh /opt/glove/entrypoint.sh

# Baked home is overlaid by the per-session bind mount; keep it world-writable
# so an arbitrary runtime uid can use it if the mount is ever absent.
RUN mkdir -p /home/agent && chmod 0777 /home/agent
ENV HOME=/home/agent
WORKDIR /work

# The entrypoint validates the enforcer policies then execs glove's compose
# `command` (for nono: `nono run --profile harness.json -- vibe …`; else bare vibe).
ENTRYPOINT ["/opt/glove/entrypoint.sh"]
