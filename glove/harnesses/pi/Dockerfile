# glove/pi — Pi coding agent inside the sandbox (DESIGN.md A.3 + PLAN §4.2/§5.2).
# Based on Pi's own plain-Docker recipe, plus a media-analysis toolchain (the
# sandbox has no egress, so analysis is in-box), glove's baked extensions
# (searxng web_search + a browser bridge, since Pi has no MCP client of its own),
# and the ring-1 enforcer: the nono binary + the glove enforcer extension that
# routes every shell command through the per-command sandbox policy.
FROM node:24-bookworm-slim

# Ring-1 enforcer: pinned nono binary (PLAN §4.2). glove/enforcers/nono/version.py
# holds the source of truth; keep this ref in sync (`glove build` warns on drift).
COPY --from=ghcr.io/nolabs-ai/nono:0.75.0 /usr/bin/nono /usr/bin/nono

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash ca-certificates git ripgrep curl \
       ffmpeg imagemagick webp libimage-exiftool-perl \
       python3 python3-pil \
       fd-find \
    && ln -s "$(command -v fdfind)" /usr/local/bin/fd \
    && rm -rf /var/lib/apt/lists/*
RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent

# glove's extensions, with their npm deps installed at build time so jiti can
# resolve them at runtime. Loaded via `pi -e /opt/glove/pi-extensions/<name>`.
# The `enforcer` extension is pure node builtins (no deps to install).
COPY extensions /opt/glove/pi-extensions
RUN cd /opt/glove/pi-extensions/searxng && npm install --no-audit --no-fund \
    && cd /opt/glove/pi-extensions/browser && npm install --no-audit --no-fund

# Baked entrypoint validates the enforcer policies then execs the compose command.
COPY entrypoint.sh /opt/glove/entrypoint.sh
RUN chmod 0755 /opt/glove/entrypoint.sh

RUN mkdir -p /home/agent && chmod 0777 /home/agent
ENV HOME=/home/agent
WORKDIR /work

# The entrypoint execs glove's compose `command` (for nono:
# `nono run --profile harness.json -- pi -e … -e … -e enforcer`; for none: bare pi).
ENTRYPOINT ["/opt/glove/entrypoint.sh"]
