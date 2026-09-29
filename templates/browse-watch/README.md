# browse-watch template

Web tasks with Pi in a **browser you can watch**. Chromium runs headed on a
VNC display inside a hardened sidecar (the `playwright` extension's `novnc`
mode). Its only way out is the session's egress (direct, vpn or tor); the
harness reaches it only through the Playwright MCP.

```sh
glove new browse-watch ~/work/tickets && cd ~/work/tickets
$EDITOR glove-session.yml        # llm settings (every <set-me>), pick the egress
glove check && glove up
glove playwright view            # in another terminal: the live browser, view-only
```

`glove playwright view` opens noVNC in your browser through a loopback tunnel
that exists only while the command runs; nothing is published. To take over
(a CAPTCHA, a login), set `playwright.allow_control: true`, relaunch, and use
`glove playwright view --control`. **Whatever you type there is visible to the
agent** (screenshots and page snapshots). With `profile: session`, cookies and
logins persist under `.glove/`.

On Podman set `playwright.chromium_sandbox: "off"`: Podman's compose cannot
apply the seccomp profile Chromium's sandbox needs, and glove refuses rather
than dropping it silently.
