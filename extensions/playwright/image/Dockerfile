# glove `playwright` browser sidecar: Chromium + the Playwright MCP
# (`playwright-core mcp`, pinned in package.json/package-lock.json), and for
# `mode: novnc` a TigerVNC display with websockify + noVNC bound to the
# container's own loopback. glove runs it as the session uid, cap-less, with a
# read-only rootfs, on an internal network whose only peers are two forwarders.
FROM mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      tigervnc-standalone-server tigervnc-tools novnc python3-websockify socat fonts-noto-core \
      libnss3-tools python3-xlib \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/glove/pw
COPY package.json package-lock.json ./
# No runtime `npx -y`: the MCP is installed from the committed lockfile.
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force \
    && ln -s /opt/glove/pw/node_modules/.bin/playwright-core /usr/local/bin/playwright-core

COPY glove-pw-start glove-pw-capture /usr/local/bin/
# the `dd` trigger relay (opt-in, `playwright.dd_relay`): relayd serves the
# `dd` channel in this container, beside the X display the pinned commands
# act on. relayd.py is a vendored copy of extensions/relay/image/relayd.py
# (keep in lockstep: re-copy when it changes); the policy and the two pinned
# executables are reviewed, and relay_policy.py pins their SHA-256s.
COPY relayd.py /usr/local/bin/relayd
COPY relay_policy.py dd_execute.py dd_preflight.py /opt/glove/dd/
RUN chmod 0755 /usr/local/bin/relayd /opt/glove/dd/dd_execute.py /opt/glove/dd/dd_preflight.py
# novnc: keeps the page the agent acts on in front (mcp.json's browser.initPage);
# the MCP deletes a staged download once it has copied it (glove-pw-start)
COPY glove-pw-front.js glove-pw-staged.js /opt/glove/pw/
# a playwright-core that saves a download some other way fails the build here
RUN grep -q 'promises.copyFile(localPath, params2.path)' node_modules/playwright-core/lib/coreBundle.js
RUN chmod 0755 /usr/local/bin/glove-pw-start /usr/local/bin/glove-pw-capture \
    && mkdir -p /data/output /data/uploads /data/staging /data/profile /etc/glove/playwright \
    && chmod 0777 /data/output /data/profile

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright NODE_PATH=/opt/glove/pw/node_modules
WORKDIR /data/uploads
CMD ["glove-pw-start", "headless"]
