# playwright — a real Chromium for the agent

Provides the `browser` slot. **v3 M2 ships `mode: host` only**; the sidecar
modes (`headless`, and `novnc` for watching/controlling) follow in M7 per
`docs/planning/playwright-novnc-handoff.md`.

```yaml
extensions:
  playwright:
    mode: host
    # port: 8931          host MCP port
    # cdp_port: 9222      host Chrome remote-debugging port
    # keep_browser: false leave Chrome running after `glove down`
    # tools: [...]        the browser_* tools Pi exposes
```

## Host mode

glove starts two host services in tmux: a headed Chrome (system Chrome, else
Playwright's Chrome for Testing) with a per-session profile under the session's
extension state, and `npx -y playwright-core@1.63.0 mcp` attached to it over
CDP with `--allowed-hosts glove-<id>-browser:<port>`. The harness reaches the
MCP only through the `browser` forwarder.

**Exposure.** This is the highest-exposure browser mode: the browser runs as
you, on your desktop, with your network (no VPN/Tor), and any local process can
drive its CDP port while it runs. Playwright's MCP always exposes
`browser_run_code_unsafe`, which runs arbitrary JavaScript in the MCP process on
your Mac. Pi's extension never exposes it in host mode; Vibe cannot filter MCP
tools, so `vibe` + host mode is refused unless you set `i_accept_host_rce: true`.
