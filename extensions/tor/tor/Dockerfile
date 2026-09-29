# glove `tor` egress: Tor as a SOCKS proxy. Runs as the session's uid (glove
# sets `user:`), read-only rootfs, no capabilities; state lives on a tmpfs.
FROM docker.io/library/alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache tor
COPY torrc /etc/glove/torrc
EXPOSE 9150
CMD ["tor", "-f", "/etc/glove/torrc"]
