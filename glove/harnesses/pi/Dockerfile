# glove/pi — Pi coding agent inside the sandbox (DESIGN.md A.3).
# Based on Pi's own plain-Docker recipe, plus a media-analysis toolchain (the
# sandbox has no egress, so analysis is in-box) and glove's baked extensions
# (searxng web_search + a browser bridge, since Pi has no MCP client of its own).
FROM node:24-bookworm-slim

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
COPY extensions /opt/glove/pi-extensions
RUN cd /opt/glove/pi-extensions/searxng && npm install --no-audit --no-fund \
    && cd /opt/glove/pi-extensions/browser && npm install --no-audit --no-fund

RUN mkdir -p /home/agent && chmod 0777 /home/agent
ENV HOME=/home/agent
WORKDIR /work

# No ENTRYPOINT: glove's compose supplies the `command` (pi -e … -e …).
# Pi also auto-loads user extensions from $PI_CODING_AGENT_DIR/extensions.
