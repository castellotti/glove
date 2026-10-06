# Minimal single-purpose forwarder sidecar (DESIGN.md A.5).
# socat for TCP forwarding; openssh-client for `ssh -N -L` LAN tunnels.
FROM alpine:3.20

RUN apk add --no-cache socat openssh-client
COPY --chmod=0755 lan-forward /usr/local/bin/glove-lan-forward

# ENTRYPOINT is socat; compose supplies the address pair as `command:`, e.g.
#   TCP-LISTEN:8080,fork,reuseaddr TCP:host.docker.internal:8899
# A `via: lan` forwarder whose target is a name runs glove-lan-forward instead.
ENTRYPOINT ["socat"]
CMD ["-h"]
