# glove srt layer: `enforcer: srt` and `enforcer: nono+srt` run on
# `<harness image>-srt`, which is this overlay on the harness image (BASE).
#
# - srt (sandbox-runtime), pinned, with its own Node so it does not depend on
#   the harness's (Vibe has none);
# - bubblewrap, socat and ripgrep (srt's runtime dependencies);
# - glove's apply-seccomp: srt's own source at the pinned tag, compiled with
#   glove-tighten's filter (srt's AF_UNIX/io_uring rules + no namespaces, no
#   mounts), so nothing srt wraps can use the userns surface the container's
#   nested-userns seccomp profile had to open. glove points srt at it with
#   `seccomp.applyPath`; the entrypoint refuses to start without it.
# - glove-srt.mjs: srt's library around the harness (nono+srt), without a
#   network namespace (srt's CLI always makes one).
# glove-pty (the TUI relay) is in every harness base image already.
ARG BASE
ARG SRT_VERSION=0.0.77

FROM debian:bookworm-slim AS build
# v0.0.77 (git ls-remote https://github.com/anthropics/sandbox-runtime refs/tags/v0.0.77)
ARG SRT_COMMIT=6fa731368807419ee157f9a3fac955fefe1019c6
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git gcc libc6-dev libseccomp-dev xxd \
    && rm -rf /var/lib/apt/lists/*
RUN git init -q /srt && git -C /srt fetch -q --depth 1 https://github.com/anthropics/sandbox-runtime.git "$SRT_COMMIT" \
    && git -C /srt checkout -q FETCH_HEAD && test "$(git -C /srt rev-parse HEAD)" = "$SRT_COMMIT"
COPY glove-tighten.c /src/
WORKDIR /src
RUN gcc -static -O2 -Wall -Wextra -o glove-tighten glove-tighten.c -lseccomp \
    && ./glove-tighten filter.bpf \
    && { echo 'static const unsigned char unix_block_bpf[] = {'; xxd -i < filter.bpf; echo '};'; } > unix-block-bpf.h \
    && gcc -static -O2 -Wall -Wextra -I. -o apply-seccomp /srt/vendor/seccomp-src/apply-seccomp.c \
    && strip apply-seccomp

FROM node:24-bookworm-slim AS srt
ARG SRT_VERSION
RUN npm install -g --prefix /opt/glove/srt/npm "@anthropic-ai/sandbox-runtime@${SRT_VERSION}"

FROM ${BASE}
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap socat ripgrep \
    && rm -rf /var/lib/apt/lists/*
COPY --from=srt /usr/local/bin/node /opt/glove/srt/node
COPY --from=srt /opt/glove/srt/npm /opt/glove/srt/npm
COPY --from=build /src/apply-seccomp /opt/glove/srt/
COPY glove-srt.mjs /opt/glove/srt/glove-srt.mjs
RUN printf '#!/bin/sh\nexec /opt/glove/srt/node /opt/glove/srt/npm/lib/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js "$@"\n' \
      > /usr/local/bin/srt && chmod 0755 /usr/local/bin/srt && srt --version
