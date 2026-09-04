# Setup: Pi against a remote LLM, with a host browser

A complete, reproducible setup for the **Pi** harness that:

- talks to a **remote OpenAI-compatible LLM** (e.g. llama.cpp on another machine)
  over an SSH tunnel,
- sees **only its own working directory**,
- reaches the web solely through a **dedicated headed Playwright browser** on the
  host that you can watch.

Copy **[`examples/pi-remote-llm.glove.yaml`](../examples/pi-remote-llm.glove.yaml)**
as your starting config; this doc explains the pieces and the non-obvious bits.

```sh
cd ~/path/to/your/project
glove init pi --from <glove-repo>/examples/pi-remote-llm.glove.yaml
$EDITOR ~/.glove/envs/<env-id>/glove.yaml     # set host, model, API key
glove doctor --env <env-id> --browser host-mcp
glove pi --dry-run                            # preview
glove pi                                      # launch
```

`init` copies the example into `~/.glove/envs/<env-id>/glove.yaml` (outside your
repo). Put the **real API key there**, never in the repo.

## The LLM over an SSH tunnel

The harness container is attached only to an `internal: true` bridge: no route
off the host, and it can't resolve mDNS (`.local`) or reach the LAN. So the LLM
is bridged in through a single host-loopback port:

- a **host service** runs `ssh -N -L 127.0.0.1:8899:127.0.0.1:8080 <remote>`,
  forwarding a local port to the model's port on the remote (needs passwordless
  SSH to the remote);
- an **`llm` forwarder sidecar** targets `host.docker.internal:8899`, so the
  harness reaches `http://glove-<session>-llm:8080/v1`.

glove starts the tunnel in a detached tmux session, waits for the port, and
reuses a live one. Nothing about the remote host leaks into the harness config.

## Model, thinking, images, context

glove synthesises Pi's `models.json`/`settings.json` from the config:

- `model:` — must match what the endpoint advertises at
  `curl http://<remote>:8080/v1/models`.
- `contextWindow` is pinned to **262144** and images are enabled
  (`input: ["text","image"]`) for the generated model entry.
- Raise the default reasoning effort with
  `harness_config.settings.defaultThinkingLevel` (`off|low|medium|xhigh`).
- Override any generated model field via `harness_config.model` (e.g.
  `contextWindow`, `maxTokens`).
- **Sampling** (`temperature`, `top_p`, `top_k`, `min_p`, penalties) is **not**
  sent by Pi — pin it **server-side** where the model runs (e.g. llama.cpp flags).

## API key handling

`llm_api_key` lives in `~/.glove/envs/<env-id>/glove.yaml` (outside the repo,
readable only by you) and glove injects it inline into Pi's `models.json`. The
sandboxed shell **cannot** read it: ring 1 hides the config home and strips
secret-shaped env vars from every command.

## Docker Desktop (macOS/Windows)

Supported out of the box. Note that the `/home/agent` bind mount is a
virtiofs/gRPC-FUSE share which cannot host a Unix-domain socket; glove backs the
nono enforcer's state roots with tmpfs so its control socket works there (no
action needed on your part).

## Browser (`host-mcp`, the default)

The harness can't open a browser itself (it's offline). `host-mcp` runs a
**Playwright MCP server on the host**, drives a real headed browser you can
watch, and bridges the harness to it through one forwarder sidecar. The agent's
`browser_*` tools speak to that endpoint; shell commands can't (ring 1 blocks
their network), so a prompt-injected `curl` can't reach the browser or the web.

```
 harness container ──internal net──▶ glove-<session>-browser (forwarder)
   pi `browser` extension                   │ socat
   (reads BROWSER_MCP_URL)                  ▼
                                    host 127.0.0.1:8931  (Playwright MCP, npx)
                                           │ launches / drives
                                           ▼
                                    headed browser on your desktop (you watch)
                                    screenshots ─▶ <workdir>/research/<collection>/media
```

Declaring a `browser` service makes glove set `BROWSER_MCP_URL` for Pi's baked
`browser` extension. `--allowed-hosts` on the MCP is pinned to the sidecar
hostname, so only requests arriving through the forwarder are accepted.

### Host prerequisites

- **Node + npx** (`glove doctor` checks these).
- **A Chromium-family browser for Playwright to drive** — the step that trips
  people up, because of how `@playwright/mcp` picks a browser.

### The `--browser` gotcha

`@playwright/mcp`'s `--browser` accepts only **channels** — `chrome`, `msedge`,
`firefox`, `webkit` — with **no `chromium` value**, and it **defaults to the
`chrome` channel** (a *system* Google Chrome). With no Chrome installed you get:

```
Chromium distribution 'chrome' is not found at /Applications/Google Chrome.app/...
Run "npx playwright install chrome"
```

Three ways to satisfy it:

1. **Dedicated Playwright Chromium — recommended, no branded browser.** Use
   Playwright's own **Chrome for Testing** (a Chromium build Playwright manages,
   isolated from your daily browser). Install once (persists):

   ```sh
   npx playwright install chromium
   ```

   Then point the MCP at it with `--executable-path`, resolved by glob so it
   survives revision bumps (macOS shown; on Linux the binary is
   `~/.cache/ms-playwright/chromium-<rev>/chrome-linux/chrome`):

   ```yaml
   host_services:
     - name: playwright
       command: >-
         npx @playwright/mcp@latest --host 127.0.0.1 --port 8931
         --allowed-hosts glove-{session}-browser:8931 --shared-browser-context
         --output-dir {media_dir}
         --executable-path "$(ls -d ~/Library/Caches/ms-playwright/chromium-*/chrome-mac*/*.app/Contents/MacOS/* 2>/dev/null | grep -i 'for Testing' | sort -V | tail -1)"
       ready_port: 8931
   ```

   `glove doctor --browser host-mcp` prints the detected Chrome for Testing path
   when no system Chrome is present.

2. **A system Chrome/Brave via CDP.** Launch it headed with
   `--remote-debugging-port=9222` and let the MCP attach with
   `--cdp-endpoint http://127.0.0.1:9222`. This is what the built-in provider
   block (`browser: { provider: host-mcp }`, or `glove pi --browser host-mcp`)
   does — it adds a `chrome` host service (Google Chrome) plus a `playwright`
   host service. Override the `chrome` command to use a different Chromium
   browser (e.g. Brave). See `examples/pi-local.glove.yaml`.

3. **Install Google Chrome.** `npx playwright install chrome`, or install Chrome
   normally, so the default `chrome` channel resolves.

### Enabling it

- **Provider block:** `browser: { provider: host-mcp, port: 8931 }` — auto-wires
  the forwarder + `chrome` + `playwright` host services (assumes a system Chrome,
  option 2/3).
- **Hand-wired** (recommended for the dedicated Chrome-for-Testing setup, option
  1): declare the `browser` service and a `playwright` host service yourself, as
  in `examples/pi-remote-llm.glove.yaml`.

Screenshots taken with no custom filename land in
`<workdir>/research/<collection>/media/` (glove pre-creates it).

## Security recap

The container is internal-only; the LLM and browser forwarders are the only
routable endpoints. The browser endpoint is in the **harness** ring-1 policy but
not the **tool** policy, so `browser_*` tools can use it while shell commands
have no network at all. See **[SECURITY.md](SECURITY.md)** for the full model.
