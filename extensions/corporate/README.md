# corporate

An egress provider for **corporate resources only**: a netgate proxy (the `gate`
library, `--upstream direct`) that refuses everything except the operator's
allowlist, reached over this machine's corporate VPN. Docker Desktop and Podman
machine send container traffic through the host's network stack, so the VPN's
routes and split DNS apply. Flows are labelled `route: corporate`.

```yaml
extensions:
  corporate:
    allow_domains: ["*.corp.example", "git.example.internal"]   # "*.x" = subdomains
    allow_cidrs: ["10.20.0.0/16"]
    from_interface: utun4      # optional (macOS): also allow the host's routes via it
    dns: host                  # host | <IPv4 of a corporate DNS server>
    tcp: [{name: git-ssh, to: "git.example.internal:22"}]   # → glove-<id>-git-ssh:22
    probe_url: https://wiki.corp.example/                   # optional check at `glove up`
  webfetch: {}
  observe: {}
```

- **Default block.** Only the allowlist passes. Names are resolved by the gate
  (`dns`), the **resolved address** is checked, and that address is dialled.
- **Guard exceptions.** Corporate hosts are private, which the SSRF guard would
  refuse, so the allowlist is also the guard's exception list: for this gate,
  for observe's gate in front of it, and for `web_fetch`'s own pre-check. It
  comes only from `glove-session.yml` — never from `rules.json`, which has no
  key for it and which this gate does not read.
- **Always refused**, whatever the allowlist: loopback, link-local and cloud
  metadata, multicast, the runtime's host gateway, the session's own network,
  `host.docker.internal`-style names.
- **`from_interface`** reads `netstat -rn -f inet` at plan time; the routes are
  shown in `glove plan` and stored in `.glove/effective.yml`. The default route
  is never included (a full-tunnel VPN would otherwise allow everything).
- **Verify** at `glove up`: the gate is up, `https://example.com` is refused
  through it (`http-refused`), and `probe_url` answers (`http-ok`).

## Checking it live

`tests/integration/test_corporate.sh` (`RT=podman` too) checks the mechanism
with a public host standing in for a corporate one. To check the real thing,
with the corporate VPN connected, from the glove repo:

```sh
glove new corporate /tmp/corp-check && cd /tmp/corp-check
$EDITOR glove-session.yml   # llm, and corporate: allow_domains/probe_url for one internal host
glove check && glove up     # verify: example.com refused, probe_url answers
```

Then in Pi: `web_fetch` the internal URL (works) and `https://example.com`
(refused by policy).
