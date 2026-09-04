# Minimal single-purpose forwarder sidecar (DESIGN.md A.5).
# socat for TCP forwarding; openssh-client for `ssh -N -L` LAN tunnels.
FROM alpine:3.20

RUN apk add --no-cache socat openssh-client

# ENTRYPOINT is socat; compose supplies the address pair as `command:`, e.g.
#   TCP-LISTEN:8080,fork,reuseaddr TCP:host.docker.internal:8899
ENTRYPOINT ["socat"]
CMD ["-h"]
