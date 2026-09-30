# glove `direct` egress: a plain forward HTTP proxy (tinyproxy). Runs as the
# session's uid (glove sets `user:`), read-only rootfs, no capabilities.
FROM docker.io/library/alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache tinyproxy
COPY tinyproxy.conf tinyproxy.filter /etc/glove/
EXPOSE 8888
ENTRYPOINT ["tinyproxy", "-d", "-c", "/etc/glove/tinyproxy.conf"]
