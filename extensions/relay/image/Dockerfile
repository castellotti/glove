# glove `relay` sidecar image: relayd.py (the sidecar half of a relay) plus the
# tools relayed commands run: git and ssh (Debian's) and gh (the official release,
# pinned by version and checksum). libnss-wrapper gives the session uid a passwd
# entry from /tmp (ssh refuses to run without one; the rootfs is read-only). Each consumer (e.g. `github`) runs it with
# its own policy file, bound read-only. glove runs it as the session uid,
# cap-less, with a read-only rootfs, on an internal network whose only way out
# is the egress proxy (or a gate in front of it).
FROM docker.io/library/python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

ARG TARGETARCH
ARG GH_VERSION=2.102.0
ARG GH_SHA256_AMD64=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386
ARG GH_SHA256_ARM64=7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484

ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates openssh-client libnss-wrapper \
    && rm -rf /var/lib/apt/lists/*
ADD https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${TARGETARCH}.tar.gz /tmp/gh.tar.gz
RUN case "$TARGETARCH" in amd64) sum=$GH_SHA256_AMD64;; arm64) sum=$GH_SHA256_ARM64;; *) exit 1;; esac \
    && echo "$sum  /tmp/gh.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/gh.tar.gz -C /tmp \
    && install -m 0755 /tmp/gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh /usr/local/bin/gh \
    && rm -rf /tmp/gh.tar.gz /tmp/gh_* \
    && gh --version && git --version && ssh -V

COPY relayd.py /opt/glove/relay/relayd.py
CMD ["python3", "/opt/glove/relay/relayd.py", "--help"]
