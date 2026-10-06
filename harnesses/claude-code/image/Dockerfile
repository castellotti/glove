# glove/claude-code — Anthropic's Claude Code inside the sandbox.
# Minimal base: the native Claude Code binary + the ring-1 enforcer (the nono
# binary, glove-pty, and glove-cc-prefix, the shell prefix that runs every Bash
# tool / `!` / hook / MCP stdio command under the tool wrapper). Optional
# capabilities are opt-in extensions composed into a per-session image variant.
# glove-pty (glove/enforcers/pty, passed as the `glovepty` build context): tool
# commands start with `glove-pty notty` so they cannot type into this TUI (TIOCSTI).
FROM debian:bookworm-slim AS glove-pty
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY --from=glovepty glove-pty.c /src/
RUN gcc -static -O2 -Wall -Wextra -o /src/glove-pty /src/glove-pty.c -lutil && strip /src/glove-pty

# Claude Code 2.x ships as a native glibc binary in a per-platform optional
# dependency; npm's install step puts it at bin/claude.exe. Only that file is
# kept: the final image needs no node.
FROM node:24-bookworm-slim AS claude
# The pinned release: harness.yml's `version`, passed by glove as a build arg.
ARG HARNESS_VERSION
RUN : "${HARNESS_VERSION:?glove passes harness.yml's version}" \
    && npm install -g "@anthropic-ai/claude-code@${HARNESS_VERSION}" \
    && cp /usr/local/lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe /claude

FROM debian:bookworm-slim

# Ring-1 enforcer: pinned nono binary. glove/enforcers/nono/version.py
# holds the source of truth; keep this ref in sync (`glove build` warns on drift).
COPY --from=ghcr.io/nolabs-ai/nono:0.78.0@sha256:5a213ddc296761a7ad9b6fbcb14ac0e9660f33c23b0b4eb70ea7c933231ca079 /usr/bin/nono /usr/bin/nono

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash ca-certificates git ripgrep curl procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=claude /claude /usr/local/bin/claude
RUN /usr/local/bin/claude --version

# Extra packages requested via session config `apt_packages` / `pip_packages`.
ARG GLOVE_APT=""
ARG GLOVE_PIP=""
RUN if [ -n "$GLOVE_APT" ]; then apt-get update \
      && apt-get install -y --no-install-recommends $GLOVE_APT \
      && rm -rf /var/lib/apt/lists/*; fi
RUN if [ -n "$GLOVE_PIP" ]; then \
      (command -v pip3 >/dev/null 2>&1 || (apt-get update \
        && apt-get install -y --no-install-recommends python3-pip \
        && rm -rf /var/lib/apt/lists/*)) \
      && pip3 install --break-system-packages $GLOVE_PIP; fi

# The srt enforcers (srt, nono+srt) run on `<this image>-srt`: the overlay in
# glove/enforcers/srt_image layered on top (it brings its own node).

# CLAUDE_CODE_SHELL_PREFIX (set in glove's read-only managed settings, so the
# agent's own settings cannot blank it): every command Claude Code runs goes
# through the session's tool wrapper, or fails closed.
COPY --chmod=0755 glove-cc-prefix /opt/glove/bin/glove-cc-prefix
COPY --from=glove-pty /src/glove-pty /opt/glove/bin/glove-pty
COPY --chmod=0755 --from=gloveentry entrypoint.sh /opt/glove/entrypoint.sh

RUN mkdir -p /home/agent && chmod 0777 /home/agent
ENV HOME=/home/agent
WORKDIR /work

# The entrypoint execs glove's compose `command` (for nono:
# `nono run --profile harness.json -- claude`; for none: bare claude).
ENTRYPOINT ["/opt/glove/entrypoint.sh"]
