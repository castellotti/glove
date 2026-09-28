# Setup: Pi against a remote LLM, with a host browser

A complete, reproducible setup for the **Pi** harness that:

- talks to a **remote OpenAI-compatible LLM** (e.g. llama.cpp on another machine),
- sees **only its own working directory**,
- reaches the web solely through a **dedicated headed Playwright browser** on the
  host that you can watch.

Copy **[`docs/examples/pi-remote-llm.glove.yaml`](examples/pi-remote-llm.glove.yaml)**
as your starting config; this doc explains the pieces.

```sh
cd ~/path/to/your/project
glove init pi --from <glove-repo>/docs/examples/pi-remote-llm.glove.yaml
$EDITOR ~/.glove/envs/<env-id>/glove.yaml     # remote host, model, key reference
glove doctor --env <env-id>                   # includes the extensions' checks
glove pi --dry-run                            # preview
glove pi                                      # launch
```

## The LLM (`llm` extension)

The harness container is attached only to an `internal: true` bridge: no route
off the host, no LAN, no mDNS. It reaches its model through **one forwarder**,
`glove-<session>-llm`, which the `llm` extension renders from `location:`:

- **`lan`**: the server is directly reachable on your network. Set
  `endpoint: <host>:<port>`; the forwarder dials exactly that address (over a
  session network the harness never joins).
- **`host`** with an SSH tunnel: when the server is only reachable over SSH, the
  example's `model-tunnel` host service runs
  `ssh -N -L 127.0.0.1:8899:127.0.0.1:8080 <remote>` in tmux, and the model is
  then at `location: host, endpoint: 127.0.0.1:8899`.

`model: auto` takes the single model the server lists at `/v1/models`, and
`capabilities: auto` asks the server for vision and context size (llama.cpp:
`/props`). Both run at launch from a throwaway container on the harness network,
never from the host. glove then renders Pi's `models.json`: vision →
`input: ["text","image"]`, plus `contextWindow` and `maxTokens`. Set them
explicitly with `capabilities: {vision: true, context_window: 131072}` when the
server can't be probed.

- Raise the default reasoning effort with
  `harness_config.settings.defaultThinkingLevel` (`off|low|medium|xhigh`).
- Override any generated model field via `harness_config.model`.
- **Sampling** (`temperature`, `top_p`, …) is **not** sent by Pi; pin it
  **server-side** (e.g. llama.cpp flags).

## API key handling

`extensions.llm.api_key` must be a reference: `keychain:<service>` or
`env:<VAR>`. A literal key is refused. glove resolves it in memory at launch
and passes it to the harness as `GLOVE_LLM_API_KEY`; Pi's `models.json` refers
to `"$GLOVE_LLM_API_KEY"` and never contains the key. The sandboxed shell
**cannot** read it: ring 1 hides the config home and strips secret-shaped env
vars from every command. Store the key once with
`security add-generic-password -U -a "$USER" -s <service> -w` (it prompts; the
key never appears in argv).

## Docker Desktop (macOS/Windows)

Supported out of the box. The `/home/agent` bind mount is a virtiofs/gRPC-FUSE
share that can't host a Unix-domain socket, so glove backs the nono enforcer's
state roots with tmpfs.

## Browser (`playwright` extension, `mode: host`)

The harness can't open a browser itself (it's offline). Host mode runs a
**Playwright MCP server on the host** (`playwright-core@1.63.0 mcp`, pinned),
attached over CDP to a **headed Chrome you can watch**, and bridges the harness
to it through one forwarder:

```
 harness container ──internal net──▶ glove-<session>-browser (forwarder)
   pi browser extension                     │
   (reads BROWSER_MCP_URL)                  ▼
                                    host 127.0.0.1:8931  (Playwright MCP)
                                           │ CDP :9222
                                           ▼
                                    headed Chrome on your desktop (you watch)
```

- **Which Chrome.** glove uses a system Google Chrome/Chromium if installed,
  else Playwright's **Chrome for Testing** (`npx playwright install chromium`,
  once). `glove doctor --env <env-id>` reports which it found.
- **Per session.** The Chrome profile and MCP output live in the session's
  extension state, never in your repo and never shared between sessions. Chrome
  stops on `glove down` unless `keep_browser: true`.
- **Pinned to the forwarder.** `--allowed-hosts` accepts only requests arriving
  through `glove-<session>-browser`. Shell commands can't reach it (ring 1 blocks
  their network).
- **Tools.** Pi exposes only the `tools:` setting's list, and never
  `browser_run_code_unsafe` in host mode (it runs arbitrary code in the MCP
  process, on your Mac). Vibe cannot filter MCP tools, so glove refuses
  `vibe` + host mode unless you set `i_accept_host_rce: true`.
- **No anonymity.** The browser uses your Mac's network directly.

`browser_take_screenshot` returns the image to the agent inline.

## Security recap

The container is internal-only; the LLM and browser forwarders are the only
routable endpoints. The browser endpoint is in the **harness** ring-1 policy but
not the **tool** policy, so `browser_*` tools can use it while shell commands
have no network at all. See **[SECURITY.md](SECURITY.md)** for the full model.
