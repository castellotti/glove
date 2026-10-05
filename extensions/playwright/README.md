# playwright — a real Chromium for the agent

Provides the `browser` slot: Playwright's MCP server (`playwright-core mcp`,
pinned in `image/package.json` + its lockfile), exposed to Pi as native
`browser_*` tools and to Vibe and Claude Code as the `playwright` MCP server.
Three modes:

| | `headless` (default) | `novnc` | `host` |
|---|---|---|---|
| Where Chromium runs | a hardened sidecar | the same sidecar, headed on a VNC display | your desktop (host Chrome) |
| You can watch | no (the agent gets screenshots) | yes: `glove playwright view` | yes, it's a window |
| You can take over | no | only with `allow_control: true` | always |
| Its traffic | only through the session's egress (vpn/tor/direct/corporate) | same | your network directly (refused with vpn/tor) |
| With observe/filter | every destination is a flow (`client: playwright`); rules apply at the gate | same | only the harness → MCP hop |
| Needs | an egress extension | an egress extension | node/npx + Chrome on the host |

```yaml
extensions:
  direct: {}                   # or vpn/tor/corporate: the browser's only way out
  playwright:
    mode: headless             # headless | novnc | host
    # tools: [browser_navigate, …]   the browser_* tools the agent gets (default: 12 browsing tools)
    # profile: ephemeral       # session: cookies persist in .glove/ext/playwright/profile
    # viewport: 1280x800
    # timezone: UTC            # the browser's timezone and locale (not matched to the exit)
    # locale: en-US
    # chromium_sandbox: "on"   # "off": the container is the only boundary (required on podman)
    # downloads: session       # work: what the browser saves lands in work/browser-output/
    # uploads: none            # work: browser_file_upload may send files from work/browser-uploads/
    # resources: {memory: 2g, cpus: 2, pids: 2048}
    # ca: local/corporate-ca.pem   # a private CA's PEM the sidecar trusts too (no default)
    # novnc only:
    # allow_control: false     # true: `glove playwright view --control` may click and type
    # clipboard: "off"         # off | to-browser | both
    # host only:
    # port: <free port>        # host MCP port (default: a free one, kept for the session)
    # cdp_port: <free port>    # host Chrome remote-debugging port (likewise)
    # keep_browser: false      # leave the host Chrome running after `glove down`
    # i_accept_host_rce: false # Vibe/Claude Code + host: see below
```

## Sidecar modes (`headless`, `novnc`)

```
harness ──glove-<id>-net──▶ glove-<id>-browser ──browser-net (internal)──▶ glove-<id>-pw
                             (forwarder / gate)                               │ Chromium + MCP :8931
                                                                              ▼
                                           glove-<id>-browser-egress ──egress──▶ the egress proxy
                                           (forwarder / gate, client: playwright)
```

- **`glove-<id>-pw`** runs as your uid with no capabilities, a read-only root
  filesystem, `no-new-privileges`, pids/memory/cpu limits and private IPC. It
  is only on `browser-net`, which is internal: its only peers are the two
  forwarders, so it has no DNS, no default route and no way to the harness or
  its llm endpoint. Leak prevention does not depend on Chromium honouring its
  proxy setting; the MCP fixes the proxy, the sandbox and the profile
  server-side, and never opens a CDP port.
- **Chromium's own sandbox is on** (`chromium_sandbox: "on"`) with the
  core-owned seccomp profile `chromium-userns`: glove's default profile plus
  unconditional `clone`/`clone3`/`unshare`/`chroot`, nothing else. Only a
  sidecar may request it; the harness never gets it. **On Podman** glove
  refuses it (`glove check` says so): `podman compose` cannot apply a custom
  seccomp profile. Set `chromium_sandbox: "off"` there, and the container is
  the only boundary.
- **Downloads, snapshots, screenshots** land in `.glove/ext/playwright/output/`,
  which the agent cannot read from a shell (screenshots and snapshots come back
  to it inline). `downloads: work` moves that directory to `work/browser-output/`:
  treat what lands there as hostile content.
- **Chromium phones home** even with Playwright's switches: in live runs the
  flows showed `accounts.google.com`, `clients2.google.com`,
  `update.googleapis.com` and `www.google.com`. With `filter`, block them.
- **A private CA** (`ca: <pem>`, unset by default) is for sites behind a
  TLS-intercepting proxy. The path is relative to the session directory and is
  checked at plan time with the same rules as `corporate_ca`: a regular file
  with a PEM certificate and no private key, not the session file or anything
  in `.glove/`. glove
  copies it into `.glove/ext/playwright/corporate-ca.pem` and binds it read-only
  at `/etc/glove/playwright/corporate-ca.pem`. The MCP's Node trusts it through
  `NODE_EXTRA_CA_CERTS`. Before Chromium starts, `glove-pw-start` imports every
  certificate in the bundle into the NSS db on the sidecar's tmpfs home
  (`certutil … -t "C,,"`). Trust is only added: glove never passes a flag that
  skips certificate checks. This setting is separate from the session's
  `corporate_ca` (which covers the harness), so set both. Host mode ignores it,
  because your Chrome already uses your Mac's trust store.
- The MCP always offers `browser_run_code_unsafe` (arbitrary code in the MCP
  process). glove never passes it on: Pi's extension registers only `tools`,
  Vibe gets a `disabled_tools` rule that hides every other `playwright_*`
  tool, and Claude Code gets allow rules for `tools` and a managed deny rule
  for every other tool the pinned MCP defines (`all_tools` in
  `extension.yml`), so it never offers them and no prompt can approve one. In
  the sidecar modes it would reach only the sidecar anyway.

### Watching: `glove playwright view` (`novnc`)

```sh
glove playwright view              # view-only, opens your browser
glove playwright view --control    # needs allow_control: true
glove playwright view --no-open    # print the URL instead
```

The sidecar runs TigerVNC and websockify on **its own loopback**; nothing is
published. `view` listens on `127.0.0.1:<random>` only while it runs and pipes
each connection through `docker|podman exec … socat` into the sidecar. It
refuses any request whose `Host` or `Origin` is not that listener (other pages
in your browser, DNS rebinding). The two VNC passwords (view-only and full)
are generated by the sidecar at every start, on its tmpfs; `view` reads the one
it needs into memory and gives it to noVNC in the URL fragment, which the
browser never sends to a server.

View-only is **enforced by the VNC server**: without `allow_control` it
accepts no pointer or key input from anyone, and the view-only password never
can. The clipboard is off server-side unless `clipboard: to-browser|both`.
Anything you type while in control is visible to the agent.

## Host mode

glove starts two host services in tmux: a headed Chrome (system Chrome, else
Playwright's Chrome for Testing) with a per-session profile under the
session's extension state, and `npx -y playwright-core@1.63.0 mcp` attached to
it over CDP with `--allowed-hosts glove-<id>-browser:<port>`. Both use free
loopback ports picked at the first launch and kept for the session
(`.glove/ext/playwright/host-ports.json`). The harness reaches the MCP only
through the `browser` forwarder.

**Exposure.** This is the highest-exposure mode: the browser runs as you, on
your desktop, with your network, and any local process can drive its CDP port
while it runs. It is refused when the session's egress is anonymising (vpn,
tor). `browser_run_code_unsafe` runs code on your Mac: Pi never registers it
in host mode, and Vibe hides it (Claude Code denies it), but a client-side
filter is not a boundary, so `vibe` or `claude-code` + host mode is refused
unless you set `i_accept_host_rce: true`.
