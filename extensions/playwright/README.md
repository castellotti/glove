# playwright — a real Chromium for the agent

Provides the `browser` slot: Playwright's MCP server (`playwright-core mcp`,
pinned in `image/package.json` + its lockfile), exposed to every harness as
the `playwright` MCP server (Pi and Claude Code name its tools
`mcp__playwright__browser_*`, Vibe `mcp_playwright.browser_*`).
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
    # downloads: session       # work: what the browser saves lands in <session>/browser-output/ (/work/browser-output, read-only)
    # uploads: none            # work: browser_file_upload may send files from /work/browser-uploads/ (<session>/browser-uploads/)
    # resources: {memory: 2g, cpus: 2, pids: 2048}
    # ca: local/browser-ca.pem   # a private CA's PEM the sidecar trusts too (no default)
    # storage_state: keychain:<service>   # a signed-in session the browser starts with (below)
    # login: {start_url, domains, capture}  # what `glove playwright login` stores (below)
    # novnc only:
    # allow_control: false     # true: `glove playwright view --control` may click and type
    # clipboard: "off"         # off | to-browser | both
    # recording: {}            # `glove playwright record` records your pointer input (below); needs allow_control
    #   to: session            # work: also <session>/browser-output/recordings/ (needs downloads: work)
    #   max_seconds: 600       # a capture stops itself after this
    #   motion_hz: 120         # pointer samples per second while a button is down (0: none)
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
  to it inline). `downloads: work` moves that directory to
  `<session>/browser-output/`: the sidecar writes it, and the harness sees it
  read-only at `/work/browser-output/` (a core `outputs:` directory, beside
  `work/`, so the agent cannot swap it for a link the sidecar would follow on a
  restart). Treat what lands there as hostile content. A link to a `.zip`/`.7z`
  or other binary downloads when the agent navigates to or clicks it; PDFs and
  media open in the browser instead (`web_download` saves those). Chromium
  stages a download in `.glove/ext/playwright/downloading/` (on disk, emptied at
  each launch), not in the sidecar's `/tmp` tmpfs, which counts against its
  memory; the MCP then copies it into the output directory and deletes the
  staged file, so a large file is on disk twice only while it is copied.
- **Uploads** (`uploads: work`, off by default): the agent puts a file in
  `/work/browser-uploads/` and passes its path to `browser_file_upload` (add
  that tool to `tools`). It is a core `inputs:` directory,
  `<session>/browser-uploads/`: read-write in the harness, read-only in the
  sidecar at the same path, so a compromised browser cannot plant anything
  there for the agent to write through, and the agent cannot swap it for a
  link. The MCP reads files only from there (its working directory, or the
  `/work` root Claude Code sends) and its output directory. Anything put
  there can leave through the browser. It checks the path as a string, so a
  symlink there resolves inside the sidecar and can name a sidecar file: with
  `profile: session`, the browser profile itself (see `docs/SECURITY.md`).
- **One browser context per sidecar.** Every MCP client shares it
  (`sharedBrowserContext` in the MCP's config), so a harness that restarts
  while the sidecar runs picks up the same tabs, cookies and open connections. With
  `profile: ephemeral` they last until the sidecar stops; with `session`,
  cookies outlast it (the sidecar's start clears the lock Chromium leaves in
  the profile when it is killed). A `glove filter block` applies to new
  connections, so use `--terminate` for a site the browser already has open.
- **`browser_evaluate`** (JavaScript in the page, inside the sidecar) is a
  reasonable addition to `tools` for sites that render nothing without it.
  Without it, a `javascript:` URL the agent navigates to would do the same
  (Chromium runs it in the current page, and the MCP returns the page title),
  so the sidecar's Chromium blocks typed `javascript:` URLs by managed policy
  (`URLBlocklist`, rendered to `.glove/ext/playwright/chromium-policy.json`,
  bound read-only where this Chromium build reads policies). A page's own
  handlers and `javascript:` links still work.
  `browser_run_code_unsafe` is not: it runs code in the MCP process.
- **Chromium phones home** even with Playwright's switches: in live runs the
  flows showed `accounts.google.com`, `clients2.google.com`,
  `update.googleapis.com` and `www.google.com`. With `filter`, block them.
- **A private CA.** The sidecar trusts the session's `corporate_ca`, and `ca:
  <pem>` (unset by default) adds one for the browser alone, for sites behind a
  TLS-intercepting proxy. It is a core `type: ca` setting: relative to the
  session directory and checked at plan time with the same rules as
  `corporate_ca` (a regular file with a PEM certificate and no private key, not
  the session file or anything in `.glove/`), then copied into `.glove/trust/`.
  Core builds the sidecar's CA bundle before `glove-pw-start` runs (`trust:
  [pw]`); the MCP's Node trusts the CAs through `NODE_EXTRA_CA_CERTS`, and
  before Chromium starts `glove-pw-start` imports each of them into the NSS db
  on the sidecar's tmpfs home (`certutil … -t "C,,"`). Trust is only added:
  glove never passes a flag that skips certificate checks. The harness never
  trusts `ca`. Host mode doesn't use it (your Chrome already uses your Mac's
  trust store), though it is still checked.
- The MCP always offers `browser_run_code_unsafe` (arbitrary code in the MCP
  process). glove never passes it on: Pi offers only `tools` (each server is
  `hidden` but for them) and its enforcer extension refuses any other, Vibe gets a `disabled_tools` rule that hides every other `playwright_*`
  tool, and Claude Code gets allow rules for `tools` and a managed deny rule
  for every other tool the pinned MCP defines (`all_tools` in
  `extension.yml`), so it never offers them and no prompt can approve one. In
  the sidecar modes it would reach only the sidecar anyway.
- **Moving the MCP pin:** re-list `all_tools` from the new release, bump the
  `playwright-core` version in its comment (a unit test holds it to
  `image/package-lock.json`), place each new tool for a stored session
  (`test_login.py` fails until you do), then run `test_playwright.sh
  claude-code`, which compares the list with the built image's tools, and
  `test_playwright_login.sh`, which checks the Chromium policy path still
  holds. The unit test alone passes
  a bumped comment over a stale list.

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

In `novnc`, `viewport` is the size of the VNC display **and** of Chromium's
window (at `0,0`, so the whole window is on screen). The page gets the window
minus Chromium's tab strip and address bar, about 88 px: 1280x712 for the
default `1280x800`. In `headless` the page itself is `viewport`. Each MCP client
(a harness restart starts a new one) opens its page in a **new** full-size
window on top of the others, so the agent's page can be hidden behind
another. So in `novnc` glove keeps the agent's page in front: an init page
the MCP loads (`image/glove-pw-front.js`) raises the page each of the agent's
tool calls acts on. It only raises the page; it never navigates, clicks or
reads it. It relies on two internals of the pinned MCP, and if they move it
logs one line and does nothing (the `capture` live test checks it).

### Recording your pointer input: `glove playwright record` (`recording`)

```sh
glove playwright record            # view --control + record; close the tab or Ctrl-C to stop and save
glove playwright record --no-open  # print the URL instead
glove playwright record --stop     # stop and save a capture left running (e.g. the terminal died)
```

With `recording` set (it needs `mode: novnc` and `allow_control: true`), the
brief tells the agent that when it needs you to do a step in the browser for
it, it leaves that tab in front, doesn't navigate it, and asks you to run
`record`, and that it doesn't use the browser until you say you are done. `record`
serves the viewer exactly as `view --control` does and starts a recorder in
the sidecar (`glove-pw-capture`). While the recorder runs it prints the title
of the window in front each time it changes, so you see which page you are
on. It stops 5 s after the last viewer tab closes, on Ctrl-C, or after
`max_seconds`. Only one recorder runs at a time. A second `record` while one
runs attaches and only watches; the `record` that started the capture stops
and saves it.
While a capture runs, glove stops raising the agent's page, so the agent
can't cover the window you are working in.

- **What is recorded** (only while you have armed it):
  - every button press and release, with its display coordinates and button
    mask;
  - pointer positions while a button is down, up to `motion_hz` per second;
  - a screenshot of the whole display at arm, at each press and release, and
    at stop;
  - the browser windows' titles, geometry and stacking order;
  - timings.

  The recorder listens to XI2 *raw* events on the X root window and asks the
  server where the pointer is. It never grabs, never selects input on
  Chromium's windows and never sends input. Keystrokes, the clipboard, page
  content and network traffic are never recorded.
- **Where it goes:** `.glove/ext/playwright/recordings/<id>/` (0700). With
  `to: work` it also goes to `<session>/browser-output/recordings/<id>/`,
  which the agent reads at `/work/browser-output/recordings/`. Each capture
  holds `events.jsonl`, `windows.jsonl`, `meta.json` and `shots/*.png`. The
  recorder writes to the sidecar's tmpfs; `record` copies the capture out with
  `exec … tar` and then removes it, and the sidecar gets no new mount.
- **The sidecar's output is treated as hostile** (it runs a browser):
  - only known file names are read, and sizes and the screenshot count are
    capped;
  - a PNG must start with the PNG signature;
  - every JSON line is parsed, checked against its schema and written back
    from the parsed value, and anything else is dropped and counted;
  - files are written with `O_NOFOLLOW|O_EXCL` through directory descriptors,
    so a link planted in `browser-output/` is refused, never followed;
  - page-set titles are stripped of control characters before they are
    printed.
- **Privacy:** your mouse movement is a behavioural biometric. Captures stay
  under `.glove/` (git-ignored) unless you choose `to: work`, which hands them
  to the agent.
- **Passive:** the recorder records only your own input and injects
  nothing.

### Signing in on the host: `glove playwright login` and `storage_state`

For sites behind single sign-on, especially SSO that needs your machine's
identity (a client certificate in your Keychain, MDM enrolment), you sign in
on the host and only the resulting session crosses into the sidecar.

```yaml
  playwright:
    profile: ephemeral                         # required with storage_state
    storage_state: keychain:corp-browser       # what `login` writes; the sidecar starts from it
    login:
      start_url: https://wiki.corp.example/
      domains: [corp.example, "*.corp.example"]  # the hosts whose cookies and localStorage are kept
      capture:                                 # single values for plugin relays, each to its own Keychain item
        chat-d:    {cookie: {domain: chat.example, name: d}}
        chat-xoxc: {storage: {origin: "https://app.chat.example", key: localConfig_v2, match: "xoxc-[A-Za-z0-9-]+"}}
```

```sh
glove playwright login     # sign in, press Enter: stores the state and the captures, then reloads the sidecar
glove playwright reload    # recreate the sidecar from the stored session (the agent's conversation keeps going)
glove playwright status    # also: how many cookies, and when the first expires (never a value)
```

- **`login`** starts a **dedicated** Chrome on your machine: a fresh profile
  under `.glove/ext/playwright/login-profile/`, deleted afterwards (`--keep-profile` keeps
  it for the next login). Your own Chrome and its profile are never touched.
  glove drives it over **CDP on a pipe** (`--remote-debugging-pipe`), so it
  opens no debugging port that another local process could reach. Sign in, and
  Chrome offers your Keychain identity if the IdP asks for one (as your own
  Chrome does; untested here, see below). Leave open the
  tabs whose localStorage you need (CDP reads an origin's storage only through
  a tab of it), then press Enter. If something named is missing, `login` says
  what (never a value) and waits for Enter again; Ctrl-C stores nothing.
- **What is stored:** the cookies (HttpOnly ones included) and open tabs'
  localStorage of the hosts in `domains` only (`x` is x itself, `*.x` its
  subdomains: list both for a cookie set on the parent domain), as a Playwright
  storage state; and each `capture` value (a cookie by domain and name, or a
  localStorage key, optionally narrowed by a regex). Each goes to the Keychain
  on stdin. Nothing is printed, put in argv or written to a file. `login`
  lists what it left out by host and count. A long value is stored in parts
  (`<service>.part<n>`, see `glove keychain set`).
- **Seeding:** `storage_state` (a `keychain:` reference when `login` writes it)
  is read at `glove up` and handed to the sidecar in its environment, gzipped
  (an env string tops out at 128 KB: `login.domains` narrows a larger one).
  `glove-pw-start` writes it 0600 to the sidecar's tmpfs, unsets the variable
  before the MCP and Chromium start, and passes `--storage-state`: every new
  browser context starts signed in. A persistent profile ignores a storage
  state, so `profile: session` is refused with it, and so is `mode: host`.
- **Behind `corporate`:** the browser must reach `start_url`'s host and every
  host in `domains`, so `glove check` warns about one `allow_domains` doesn't
  admit (a host on a private address needs `allow_cidrs` too).
- **Expiry:** SSO cookies are short-lived. `glove playwright status` shows the
  earliest cookie expiry; run `login` again when it passes. `login` reloads the
  sidecar itself when it is running (`--no-reload` doesn't); a plugin relay
  using a captured value needs `glove skills reload <plugin>`.
- **What the agent can and can't do:** it browses as you on those hosts, as
  with `profile: session`. It never sees a value: the tools that would hand
  over the stored session are refused in `tools` while `storage_state` is set
  (`browser_cookie_*`, `browser_localstorage_*`, `browser_sessionstorage_*`,
  `browser_storage_state`, `browser_set_storage_state`, `browser_evaluate`,
  `browser_run_code_unsafe`, `browser_network_request` (a request's headers),
  `browser_start_tracing` (a trace holds every request's headers) and
  `browser_route` (a body the agent writes would run as the signed-in page)), so is
  `uploads: work` (a link in `/work/browser-uploads/` resolves inside the
  sidecar, where it could name the stored state); typed `javascript:` URLs are
  blocked (above), and the MCP refuses `file:` URLs. A page on one of those hosts can still show
  what the site itself puts in it.
- **Tested:** `tests/integration/test_playwright_login.sh`: a stand-in sign-on
  site (a parent-domain HttpOnly SSO cookie, a tracker's cookie, a chat app's
  cookie and localStorage token) behind the `corporate` egress, a real host
  Chrome (headless) signing in through `login`, then the agent's browser
  signed in only after `reload`, through the gate; a `javascript:` probe in
  the signed-in page reads nothing. 20/20 with Pi and Claude
  Code on Docker (nono+srt), and Pi on Podman (nono, `SANDBOX=off`). The
  client-certificate handshake against a real IdP is **untested** here (it
  needs an MDM-enrolled identity).

## Host mode

`glove up` starts two processes on the host: a headed Chrome (system Chrome,
else Playwright's Chrome for Testing) with a per-session profile under the
session's extension state, and `npx -y playwright-core@1.63.0 mcp` attached to
it over CDP with `--allowed-hosts glove-<id>-browser:<port>`. Both use free
loopback ports picked at the first launch and kept for the session
(`.glove/ext/playwright/host-ports.json`). The harness reaches the MCP only
through the `browser` forwarder.

They run in tmux (`tmux attach -t glove-<id>-host-playwright-chrome`, or
`-mcp`); without tmux, as background processes logging under
`.glove/ext/playwright/host-logs/`. One whose port already answers is reused.
`glove down` stops both, except Chrome with `keep_browser: true`. `glove plan`
and `glove policy` show both commands before you launch.

**Exposure.** This is the highest-exposure mode: the browser runs as you, on
your desktop, with your network, and any local process can drive its CDP port
while it runs. It is refused when the session's egress is anonymising (vpn,
tor). `browser_run_code_unsafe` runs code on your Mac: in host mode glove
leaves it out of the allowlist even if `tools` lists it. Pi's enforcer
extension, the code that wraps its every shell command, refuses a tool its
inventory lacks; Vibe hides it (Claude Code denies it), but that client-side
filter is not a boundary, so `vibe` or `claude-code` + host mode is refused
unless you set `i_accept_host_rce: true`.
