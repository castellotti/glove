# glove `playwright` browser sidecar: Chromium + the Playwright MCP
# (`playwright-core mcp`, pinned in package.json/package-lock.json), and for
# `mode: novnc` a TigerVNC display with websockify + noVNC bound to the
# container's own loopback. glove runs it as the session uid, cap-less, with a
# read-only rootfs, on an internal network whose only peers are two forwarders.
FROM mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      tigervnc-standalone-server tigervnc-tools novnc python3-websockify socat fonts-noto-core \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/glove/pw
COPY package.json package-lock.json ./
# No runtime `npx -y`: the MCP is installed from the committed lockfile.
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force \
    && ln -s /opt/glove/pw/node_modules/.bin/playwright-core /usr/local/bin/playwright-core

COPY glove-pw-start /usr/local/bin/glove-pw-start
RUN chmod 0755 /usr/local/bin/glove-pw-start \
    && mkdir -p /data/output /data/uploads /data/profile /etc/glove/playwright \
    && chmod 0777 /data/output /data/profile

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright NODE_PATH=/opt/glove/pw/node_modules
WORKDIR /data/uploads
CMD ["glove-pw-start", "headless"]
