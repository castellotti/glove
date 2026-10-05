# glove/pi — Pi coding agent inside the sandbox.
# Minimal base: Pi's own plain-Docker recipe + the ring-1 enforcer (the nono
# binary + the glove enforcer extension that routes every shell command through
# the per-command sandbox policy). Nothing else. Optional capabilities (search,
# browser, media toolchain) are opt-in plugins composed into a per-session image
# variant when enabled — never baked into this base.
# glove-pty (glove/enforcers/pty, passed as the `glovepty` build context): tool
# commands start with `glove-pty notty` so they cannot type into this TUI (TIOCSTI).
FROM debian:bookworm-slim AS glove-pty
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY --from=glovepty glove-pty.c /src/
RUN gcc -static -O2 -Wall -Wextra -o /src/glove-pty /src/glove-pty.c -lutil && strip /src/glove-pty

FROM node:24-bookworm-slim

# Ring-1 enforcer: pinned nono binary. glove/enforcers/nono/version.py
# holds the source of truth; keep this ref in sync (`glove build` warns on drift).
COPY --from=ghcr.io/nolabs-ai/nono:0.78.0@sha256:5a213ddc296761a7ad9b6fbcb14ac0e9660f33c23b0b4eb70ea7c933231ca079 /usr/bin/nono /usr/bin/nono

ENV DEBIAN_FRONTEND=noninteractive
# fd is a core Pi tool (Pi shells out to `fd` for file search and, absent it,
# tries to download it at startup — which PI_OFFLINE=1 blocks in the sandbox),
# so it's baked into the base, not deferred to a plugin. `ln` gives the
# canonical `fd` name that Debian's fd-find package installs as `fdfind`.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       bash ca-certificates git ripgrep curl fd-find \
    && ln -s "$(command -v fdfind)" /usr/local/bin/fd \
    && rm -rf /var/lib/apt/lists/*
RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent

# Extra packages requested via session config `apt_packages` / `pip_packages`
# (glove passes them as build-args). The Vibe base already honoured these; Pi did
# not, so top-level apt_packages were silently dropped. Mirror Vibe here so e.g.
# an OCR toolchain (tesseract/poppler/ghostscript/ocrmypdf) actually lands.
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
# glove/enforcers/srt_image layered on top, never baked in here.

# The always-on ring-1 enforcer extension (pure node builtins, no deps to
# install). Loaded via `pi -e /opt/glove/pi-extensions/enforcer`. Capability
# extensions are added by plugins into a per-session image variant, not here.
COPY extensions/enforcer /opt/glove/pi-extensions/enforcer

# Baked entrypoint (glove/enforcers/entrypoint, shared by every harness, passed as
# the `gloveentry` build context) validates the enforcer policies then execs the
# compose command.
COPY --from=glove-pty /src/glove-pty /opt/glove/bin/glove-pty
COPY --chmod=0755 --from=gloveentry entrypoint.sh /opt/glove/entrypoint.sh

RUN mkdir -p /home/agent && chmod 0777 /home/agent
ENV HOME=/home/agent
WORKDIR /work

# The entrypoint execs glove's compose `command` (for nono:
# `nono run --profile harness.json -- pi -e …/enforcer`; for none: bare pi).
ENTRYPOINT ["/opt/glove/entrypoint.sh"]
