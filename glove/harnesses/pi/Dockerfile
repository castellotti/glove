# glove/pi — Pi coding agent inside the sandbox.
# Minimal base: Pi's own plain-Docker recipe + the ring-1 enforcer (the nono
# binary + the glove enforcer extension that routes every shell command through
# the per-command sandbox policy). Nothing else. Optional capabilities (search,
# browser, media toolchain) are opt-in plugins composed into a per-session image
# variant when enabled — never baked into this base.
FROM node:24-bookworm-slim

# Ring-1 enforcer: pinned nono binary. glove/enforcers/nono/version.py
# holds the source of truth; keep this ref in sync (`glove build` warns on drift).
COPY --from=ghcr.io/nolabs-ai/nono:0.75.0 /usr/bin/nono /usr/bin/nono

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

# Opt-in srt enforcer: baked only for the `-srt` image variant
# (built with --build-arg GLOVE_ENFORCER=srt). Node ≥22 is already present.
ARG GLOVE_ENFORCER=nono
RUN if [ "$GLOVE_ENFORCER" = "srt" ]; then \
      apt-get update \
      && apt-get install -y --no-install-recommends bubblewrap socat \
      && rm -rf /var/lib/apt/lists/* \
      && npm install -g @anthropic-ai/sandbox-runtime@0.0.75; \
    fi

# The always-on ring-1 enforcer extension (pure node builtins, no deps to
# install). Loaded via `pi -e /opt/glove/pi-extensions/enforcer`. Capability
# extensions are added by plugins into a per-session image variant, not here.
COPY extensions/enforcer /opt/glove/pi-extensions/enforcer

# Baked entrypoint validates the enforcer policies then execs the compose command.
COPY entrypoint.sh /opt/glove/entrypoint.sh
RUN chmod 0755 /opt/glove/entrypoint.sh

RUN mkdir -p /home/agent && chmod 0777 /home/agent
ENV HOME=/home/agent
WORKDIR /work

# The entrypoint execs glove's compose `command` (for nono:
# `nono run --profile harness.json -- pi -e …/enforcer`; for none: bare pi).
ENTRYPOINT ["/opt/glove/entrypoint.sh"]
