# corporate template

Work with an organisation's internal resources from Pi, with **no general
internet**. The session's only way out is the `corporate` egress: a netgate
proxy that refuses everything except the hosts and ranges you allow, reached
over this machine's corporate VPN (Docker Desktop and Podman machine send
container traffic through the host's network stack, so the VPN's routes and
split DNS apply).

```sh
glove new corporate ~/work/corp-1 && cd ~/work/corp-1
$EDITOR glove-session.yml        # llm + corporate allowlist (every <set-me>)
glove check && glove up
```

`glove up` starts the corporate gate and checks, before Pi starts, that
`https://example.com` is refused through it (and that `probe_url`, if set,
answers). `observe` is on: `glove observe flows` shows every destination the
session tried, allowed or refused. Add `filter: {}` to block more at run time
(`glove filter block …`); the allowlist itself only ever comes from this file.
