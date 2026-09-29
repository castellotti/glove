# glove `tor` egress: privoxy, the HTTP(S) proxy egress consumers use. It
# forwards every request to Tor by hostname (forward-socks5t) and keeps no log.
FROM docker.io/library/alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache privoxy
COPY privoxy.conf /etc/glove/privoxy.conf
EXPOSE 8118
ENTRYPOINT ["privoxy", "--no-daemon", "/etc/glove/privoxy.conf"]
