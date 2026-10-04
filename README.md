# glove

`glove` is a Python CLI that launches an agentic coding harness (Pi or Mistral
Vibe; Claude Code later) inside a **sandbox**, presents the harness's normal TUI
in your terminal, and guarantees that the harness - and every shell command,
extension, skill, or MCP server it spawns - can only touch the host directories
you explicitly exposed, can only reach the network endpoints you explicitly
allowed, and cannot escalate privilege.

**A session is a directory.** `glove new <template> <dir>` materializes one:
one file you edit (`glove-session.yml`), a `work/` folder the agent sees as
`/work`, and glove's private state in `.glove/`. `glove up` builds and starts it.
Delete the directory and the session is gone.

The sandbox is *distributed as a container image* (Docker or Podman), but the
security does not rest on the container alone: a kernel-level capability
sandbox (srt/bubblewrap around the harness and nono/Landlock around every
command on Docker; nono alone on Podman) runs *inside* the container and wraps
every command the agent executes. See [How it works](#how-it-works---three-rings-defense-in-depth).

**Minimal core + plugins.** The core (`glove/`) knows runtimes, enforcers and
session directories, and no harness by name: each harness is a **harness
plugin** in `harnesses/<name>/` (see [Harnesses](#harnesses)), and only the
selected one's code runs. Every capability is an **extension** in
`extensions/<name>/` (a declarative `extension.yml`), selected per session in
`extensions:`. An extension you don't select contributes nothing: no
containers, no mounts, no image layers. Bundled: **`llm`** (the inference
engine; required), the egress providers **`vpn`** (gluetun), **`tor`**,
**`direct`** and **`corporate`** (corporate resources only), **`search`** (a
per-session SearXNG), **`webfetch`** (Pi's `web_fetch`), **`observe`** (network
observability, read) and **`filter`** (network rules, write), **`media`**
(analysis toolchain), **`ocr`**/**`rag`** (documents) and **`playwright`** (a
real Chromium: a hardened headless sidecar, a noVNC-watched one, or the host's
Chrome). See [Extensions](#extensions).

## Quick start

glove runs from a checkout (the bundled `harnesses/`, `extensions/` and `templates/` live
next to the package), with [uv](https://docs.astral.sh/uv/), and Docker Desktop
or Podman:

```sh
git clone https://github.com/castellotti/glove && cd glove && uv sync
uv run glove doctor                     # runtime, enforcer and kernel probes
```

(The examples below write `glove` for `uv run glove`.)

**A session is a directory.** `glove new` materializes one; you edit one file and
run `glove up`. Its state lives in `<dir>/.glove/`, so deleting the directory
deletes the session (only a registry row, and what an extension explicitly
exports, stays under `~/.glove`; `glove gc` removes those).

```sh
glove new minimal ~/work/research-1     # glove-session.yml, work/, .glove/ (0700)
cd ~/work/research-1
$EDITOR glove-session.yml               # the ONE file you edit (set the llm <set-me>s)
glove check                             # schema, secrets exist (never read), doctor
glove plan                              # what it grants; renders .glove/, launches nothing
glove up                                # build → sidecars → resolve model → TUI
glove down                              # stop (glove rm: also delete .glove/)
```

`glove new` takes a bundled template (`templates/`: `minimal`, `pi-search`, `pi-rag`, `browse-watch`, `corporate`), a path to a
directory or file, or a git URL. Templates are *materialized*, not inherited:
the file is a full copy, so upgrading glove never silently widens a session.
`glove check` warns when the template changed since, and `glove new --diff`
shows how.

```
<session-dir>/
  glove-session.yml   the file you edit (no secrets: references only)
  work/               → /work (rw)
  local/              optional private host assets (e.g. hooks); never mounted
  .glove/             0700; only home/ and enforcer/ are mounted
    id                stable session id: <dirname>-<6 hex>
    compose.yml  effective.yml  baseline.yml  template.yml
    home/             → /home/agent (config, transcripts)
    enforcer/         → /etc/glove/enforcer (ro, ring-1 policies)
    ext/<name>/       per-extension state
```

### Templates

| Template | What the session is for | Extensions |
|---|---|---|
| `minimal` | a coding agent and nothing else | `llm` |
| `pi-search` | web research through a VPN (swap in `tor: {}` or `direct: {}`) | `llm`, `vpn`, `search`, `webfetch`, `ocr`, `media` |
| `pi-rag` | offline investigation of local documents and media | `llm`, `ocr`, `rag`, `media` |
| `browse-watch` | a real browser you can watch (noVNC) | `llm`, `direct`, `playwright` (`novnc`) |
| `corporate` | corporate resources over this machine's corporate VPN, nothing else | `llm`, `corporate`, `webfetch`, `observe` |

Each has a `README.md` in `templates/<name>/`. A template's private parts
(Keychain service names, VPN register hooks, local model paths) never live in
the template: `glove-session.yml` holds `keychain:<service>` references and
paths you fill in, and hooks go in the session's `local/`.

## Session file (`glove-session.yml`, schema v3)

```yaml
glove: 3
template: minimal           # provenance only
harness: pi                 # pi | vibe | claude-code (experimental)
runtime: docker             # docker | podman | apple-container|gondolin|utm (stub)
enforcer: nono+srt          # default: nono+srt on docker, nono on podman | nono | srt | none
mounts:                     # explicit extra host dirs; work/ is always /work
  - { path: ~/src/shared-lib, mode: ro }
extensions:                 # name → settings; unlisted = nothing in the session
  llm:                      # required: fills the `inference` slot
    provider: llama.cpp     # openai-compatible (any OpenAI-API server) | llama.cpp | ollama | lmstudio | openai | anthropic | mistral | openrouter
    location: host          # host (this Mac) | lan | internet
    endpoint: 127.0.0.1:8080
    model: auto             # or an id; auto = the single model /v1/models lists
    capabilities: auto      # or explicit keys, e.g. {vision: true}; probes fill the rest
    # api_key: keychain:my-llm   # a reference only (keychain:<service> | env:<VAR>)
  vpn:                      # egress: exactly one of vpn | tor | direct
    provider: mullvad       # any gluetun provider, or `custom`
    wireguard_key: keychain:my-vpn-wg
  search: {}                # per-session SearXNG behind the egress
  webfetch: {}              # Pi's web_fetch through the egress
  media: {}
  # playwright: {}           # a real Chromium in a sidecar, via the egress (mode: headless | novnc | host)
  observe: {}               # network observability (read) — see below
  # filter: {}              # network rules (write); needs observe
tools: { net: block, allow_commands: [cp, mv, rm] }
limits: { pids: 512, memory: 4g, cpus: 2 }
enforcer_options: { srt: { nested: weak } }   # nono+srt also: hide_env (default true)
protect_ide_files: false    # also ro-bind .vscode/.envrc/.mcp.json (creates empty ones if missing)
# corporate_ca: local/corporate-ca.pem   # a private CA the harness trusts too (see below)
# toolchains:                              # pinned runtimes + deps baked into the image (see below)
#   - { lang: node, version: "22.23.3", project: projects/web }
```

Relative mount paths resolve against the session directory. A mount that would
expose `.glove/`, `local/`, `glove-session.yml`, glove's home (`~/.glove`) or
another session's state is refused. The v2 keys (`workdir`, `add_dirs`, `net`,
`services`, `observe`, `name`, …) are refused with a pointer to their
replacement.

**Private CA trust (`corporate_ca`, off by default).** Behind a TLS-intercepting
proxy whose certificates come from a private CA, set `corporate_ca` to a PEM
bundle (relative to the session directory; `local/` is a good home). glove checks
at plan time (`glove check`) that it is a regular file with at least one
`-----BEGIN CERTIFICATE-----` block and **no private key** (a combined
cert-and-key PEM is refused, since the agent can read whatever is bound), and not
the session file or anything in `.glove/`. It then binds the file read-only at `/etc/glove/corporate-ca.pem` and
sets `NODE_EXTRA_CA_CERTS` to that path (an explicit `env:` entry wins). Node adds
these certificates to its built-in roots, so the public roots stay trusted and
**TLS verification is never turned off**. The PEM is a public certificate, not a
secret, so it never goes through the Keychain. Every enforcer can already read
`/etc/glove`, so no policy changes. This covers Node-based harnesses and tools
(Pi, Claude Code, `web_fetch`). Non-Node tools in the box (curl, Python
`requests`, Vibe's Python client) keep the image's trust store and won't trust
the CA. The browser sidecar is a separate container: set
`playwright: {ca: …}` as well (see Browser below). Unset, nothing renders
differently.

**Language toolchains (`toolchains`, off by default).** Shell commands have no
network, so `npm install`/`pip install` can't run in the box. `toolchains` declares
pinned runtimes and their packages, and glove installs them **at image build
time** (the build has network) into the session's derived image:

```yaml
toolchains:                       # a list; order is install and PATH order; one block per lang
  - lang: node
    version: "22.23.3"            # required, exact X.Y.Z (official tarball, SHASUMS256-checked)
    manager: npm                  # npm (default) | pnpm[@ver] | yarn[@1.x] (classic only; 2+ refused)
    project: projects/web         # optional; relative to the session dir; its manifest + lockfile are baked
    install: ci                   # npm: ci (default) | install; pnpm/yarn: frozen (default) | install
    config_files: [.npmrc]        # optional project config baked beside the manifest (public, no credentials)
    install_flags: ["--legacy-peer-deps"]  # optional flags appended to the project install
    packages: ["tsx@4.19.2"]      # optional global tools
    browsers: [chromium]          # optional Playwright engines (chromium | firefox | webkit)
  - lang: python
    version: "3.12"               # required, X.Y or X.Y.Z (uv-managed CPython; uv is pinned by glove)
    manager: uv                   # uv (default) | pip
    project: projects/tool
    install: sync                 # uv: sync (default, `uv sync --locked --no-install-project`) | requirements; pip: requirements
    packages: ["rich==15.0.0"]
```

- **Everything lands under `/opt/glove/toolchains/`.** That path is on the
  read-only rootfs and never under a runtime mount (anything baked under `/work`
  or the harness home would be hidden by the bind). Every enforcer already lets
  the harness and its commands read `/opt/glove`, so no policy changes. No mount
  can land there: glove's mount points are only `/work`, `/mnt/…` and the
  harness home.
- **The runtime finds it through env.** The image prepends the bins to `PATH`
  (Node's `bin` plus the project's `node_modules/.bin`, then the Python venv's
  `bin`). The harness env adds `PLAYWRIGHT_BROWSERS_PATH` and `VIRTUAL_ENV`.
  These are set only if absent, so an explicit `env:` entry wins. There is no
  `NODE_PATH`, because nono strips it (and `NODE_OPTIONS`/`PYTHONPATH`) from every
  wrapped command. Instead a node project's `node_modules` is linked into the
  pinned node's own global folder (`<runtime>/lib/node`), so `require` finds the
  deps from any directory under every enforcer. The harness always runs on the
  image's own interpreter, toolchain or not: Pi starts as
  `/usr/local/bin/node /usr/local/bin/pi`, and Vibe's hook runs as
  `/usr/local/bin/python3 /opt/glove/vibe-hook`. Claude Code (experimental) has
  no such pin.
- **Lockfile-strict by default.** `npm ci`, `pnpm install --frozen-lockfile`,
  `yarn install --frozen-lockfile` and `uv sync --locked --no-install-project`
  are the defaults.
  `glove check` fails early on an unknown `lang`/`manager`/`install`, a missing
  `version`, or a missing lockfile. It also refuses a `project` that isn't a
  directory or that exposes a private path (`.glove/`, `local/`, the session
  file, `~/.glove`).
- **Only the manifest and lockfile are baked** (`package.json` plus its lockfile,
  `pyproject.toml` plus `uv.lock`, or `requirements.txt`), never the project's
  tree, source, `.npmrc` or `.git`. A symlinked manifest is refused, so nothing
  outside the project is ever copied in. The project's own package is not
  installed (`--no-install-project`). The agent works on its copy under `/work`.
  So an install that needs more than those files fails at build time: npm/pnpm
  workspaces, `file:`/path dependencies, a root `postinstall` script, or a
  `requirements.txt` that includes another file.
- **Project config and install flags (`config_files`, `install_flags`, off by
  default).** Some projects only install with their own settings, e.g. a
  committed `.npmrc` with `legacy-peer-deps = true` or a private `registry`.
  `config_files` names extra files in the project directory to bake beside the
  manifest, before the install runs (`.npmrc`, `.yarnrc`, `pnpm-workspace.yaml`,
  `uv.toml`, …). Each must be a plain file name (no path, so it can't leave the
  project), a regular file (not a symlink), and not already baked by the install
  mode. Config files are **public build inputs**: image layers are not secret
  storage, so `glove check` refuses one with a credential-like key (`_auth`,
  `_authToken`, `npmAuthToken`, `password`, `token`, `secret`, …, even an
  `${ENV}` reference, including yarn v1's quoted `"//host/:_authToken" "…"`) or
  a URL with userinfo (`user:pass@`, or a bare token as `https://ghp_…@host`;
  only ssh's `git@` passes). A registry that needs a token can't be baked.
  `install_flags` appends flags to the project install command (every manager:
  npm, pnpm, yarn, uv, pip), never to the global `packages` step. Each flag is a
  single long option, `--flag` or `--flag=value` (value: letters, digits,
  `._/@:-`), and must be on the **install mode's allow-list**: e.g.
  `--legacy-peer-deps`, `--force`, `--ignore-scripts`, `--registry=…` (npm);
  `--no-dev`, `--extra=…`, `--index-url=…` (uv sync); `--no-deps`,
  `--require-hashes` (pip). Flags that move the install (`--prefix`, `--global`,
  `--target`), weaken the lockfile (`--no-frozen-lockfile`, uv's `--frozen`) or
  TLS (`--trusted-host`), or load another config file are not on it; the error
  lists what is. Shell metacharacters (`;`, `&&`, `$()`, backticks) are refused,
  and so is a URL value with credentials. All of this is checked at plan time.
  A baked `.npmrc` applies only to the project install too. Both feed the image
  tag (the file's contents, the flags), and a block without them renders
  exactly as before.
- **Content-addressed and layered for the cache.** The derived image tag changes
  with any block field and the manifest and lockfile contents, so a stale image
  is never reused. Editing the project's source never rebuilds anything. Layers
  run every block's runtime first, then global tools, then project installs and
  browsers, so a lockfile bump never re-downloads a runtime.
- **The workspace shadow.** The baked dependencies live at
  `/opt/glove/toolchains/node/project/node_modules`, not inside `/work`.
  Plain `require` finds them from anywhere and the CLIs are on `PATH`, but a
  bundler, dev server, test runner or ES `import` resolves `./node_modules` from
  the project root. So the agent's context file tells it to run `ln -s
  /opt/glove/toolchains/node/project/node_modules node_modules` in its copy under
  `/work` (the project in `/work` must match the baked lockfile). Python has no
  such problem: the venv is active wherever the command runs.
- **Browsers.** `browsers` runs `playwright install --with-deps` at build time,
  which installs the engines and their OS libraries. The engines launch offline
  from a shell command under `enforcer: srt` (with `chromiumSandbox: false`, after
  `mkdir -p "$TMPDIR"`). Under `nono` and the default `nono+srt`, nono's
  per-command profile stops Chromium starting: it is denied `/proc/self/maps`,
  `/proc/sys` and `/etc/fonts`. Widening that profile would expose `/proc`, so
  it isn't done; the agent is told. For a browser under the default enforcer,
  use the `playwright` extension (a sidecar). The engines are installed by the
  project's own `playwright` when its `package.json` depends on it, otherwise by
  the global one from `packages`.
- **OS libraries** a toolchain needs go in `apt_packages`; the two compose.

Unset, nothing toolchain-specific renders: image tags, compose env, policies and
the context file are unchanged.

Each session gets a /24 from `subnet_pool` in `~/.glove/config.yml` (default
`172.31.0.0/16`), recorded in the registry, and each of its networks a /27 of
it. Allocation avoids other sessions and the runtime's existing networks; if a
foreign network takes the range later, `glove up` re-allocates.

`.git/hooks` and `.git/config` in every rw mount are always bound read-only (and
`.git` is pinned so it can't be renamed away): an agent must not plant a hook your
Mac runs the next time you use git. See "Planted host-trusted files" in
[docs/SECURITY.md](docs/SECURITY.md).

## CLI

Session commands take an optional directory; without one they use the nearest
`glove-session.yml` at or above the current directory.

```
glove new <template|path|git-url> [DIR]      # materialize a session (DIR default: .)
glove new --diff <any> [DIR]                 # how the template changed since `glove new`
glove check [DIR] [--no-container]           # schema, placeholders, secrets exist, doctor
glove plan  [DIR] [--compose] [--resume|--session ID]   # render .glove/, print the grants
glove up    [DIR] [--resume|-r] [--session ID] [--rebuild]
glove down  [DIR] [--wipe]                   # --wipe: also volumes + the flow record
glove rm    [DIR] [--all] [--yes]            # down --wipe, delete .glove/ + exports + row
glove policy [DIR]                           # ring-1 policies + ring-0 hardening + gaps
glove ls | ps | gc [--yes]                   # registry rows (ok|missing|stale), running, prune
glove keychain set <service>                 # store a secret, prompting (never in argv)
glove doctor [--runtime R] [--enforcer E] [--json] | build [HARNESS] [--enforcer srt|nono+srt] | version
glove ext                                    # every loadable extension, origin, CLI
glove observe status [--dir D] [--json]      # (observe) gate health + per-service totals
glove observe flows  [--dir D] [--follow] [--json] [--tail N]
glove filter block  <host-glob|ip|cidr> [--port N] [--terminate] [--allow] [--note TEXT]
glove filter unblock <rule-id|target>        # (filter) only with the filter grant
glove filter rules  [--json]                 # rules + the gates' load result
glove filter validate <file|-> [--env ID] [--session ID] [--json]   # the gate's validator; pure
glove playwright view [--dir D] [--control] [--no-open]   # (playwright novnc) watch/drive the browser
glove playwright status [--dir D]
```

An extension with a `cli:` in its manifest is mounted at `glove <name> …`.

`~/.glove/registry.json` (v2, `{"v": 2, "sessions": [{id, dir, harness,
template, created, grants, subnet}]}`) indexes sessions; a v2-era registry
(a JSON list) is refused rather than overwritten; move it aside.

## Resuming a session

A conversation's transcript lives in the session's `.glove/home` (bind-mounted
at `/home/agent`) — or, with observe's `transcripts: true`, in
`~/.glove/observe/<id>/transcripts/` — **not** in the (ephemeral) container. So
you can reopen one:

- `glove up --resume` (`-r`) — reopen the **most recent** conversation. glove
  checks a transcript exists, then defers to the harness's own continue-last,
  so use `--session <id>` when you need to be sure exactly which one reopens.
- `glove up --session <id>` — reopen a **specific** conversation (full or
  partial UUID, or a transcript path). glove resolves it to that transcript's
  canonical id before handing it to the harness.

Because glove re-renders the whole sandbox from the *current* config on every
run, **editing `glove-session.yml` before resuming changes the grants for the
resumed conversation** — e.g. add an extension or a mount you now need, then
resume with the new grant live. When a resume run grants **broader** access than
the session's `.glove/baseline.yml` (mounts, extensions, `allow_root`,
`allow_sensitive`), glove
prints a prominent warning: the prior conversation context (which may include
prompt-injected instructions) will run with the wider reach.

> Transcripts live under the session's `.glove/home/`. This is durable on-disk
> state — don't sync that tree to anywhere untrusted (`.glove/` carries a
> `.gitignore` of `*`, so a session inside a git repo never commits it).
>
> **The LLM API key is never in a file.** `extensions.llm.api_key` must be a
> reference: `keychain:<service>` (a macOS Keychain generic password) or
> `env:<VAR>`; a literal key is refused. glove resolves it in memory when the
> session launches (never during `glove plan` or `glove check`, which only checks
> that the Keychain item exists), and the effective config records
> only the reference. The compose file declares `GLOVE_LLM_API_KEY` without a value, glove supplies it in
> the environment of `compose` when it starts the session, and Pi's `models.json`
> refers to it as `"$GLOVE_LLM_API_KEY"`. Inside the sandbox only the harness
> process sees it; ring 1 strips it from every shell command. Store a key with
> `glove keychain set <service>` (it prompts; the key is never in argv).

## Harnesses

A harness is a directory under `harnesses/`, beside `extensions/`:

```
harnesses/<name>/
  harness.yml    # the profile (data): image tag, TUI entry, config home, context file,
                 # transcript dirs, resume flags, which neutral contributions it renders
  adapter.py     # renders its native config; may add entry args / image lines (optional)
  image/         # the base image's build context (Dockerfile, ring-1 glue)
  tests/
```

Core reads every `harness.yml` and imports `adapter.py` by path only for the
harness a session selects. Every image bakes the one shared entrypoint
(`glove/enforcers/entrypoint`, the `gloveentry` build context) that validates the
ring-1 policies before the harness starts. Bundled: `pi`, `vibe`, and
`claude-code` (experimental). The names are stable: `~/.glove/registry.json`
and observe's `session.json` record them, and external monitors (Layman) pick a
transcript parser by them.

## Extensions

An extension is a directory under `extensions/` with an `extension.yml`
manifest (`api: 1`): its settings schema, the endpoints (forwarders) the
harness may reach, image layers, harness contributions (MCP servers, skills, a
harness's own code), a brief for the agent, and optionally hardened sidecars.
Core validates all of it:

- **Settings** are typed; unknown keys, `<set-me>` placeholders and literal
  secrets are errors. Secrets are `keychain:`/`env:` references, resolved in
  memory and passed to containers only as compose secrets from glove's
  environment, mounted at `/run/glove-secrets/<name>` (`session.secrets_dir`
  in fragments; podman hides `/run/secrets` under its own mount).
- **Slots** are exclusive: `inference` (required; `llm`), `egress`, `browser`.
  Two providers of one slot are refused.
- **Sidecars** get the hardening set (non-root, `cap_drop: ALL`,
  `no-new-privileges`, read-only rootfs, seccomp, pids/memory limits) from core;
  a fragment cannot set a security key. Exceptions come only from the manifest's
  `privileges:`, drawn from an allowlist, and are shown in `glove policy`
  (`low_ports` lets a sidecar listen below 1024 in its own network namespace,
  as docker allows every container by default and podman does not).
  A seccomp exception names a core profile (`chromium-userns`, for Chromium's
  sandbox; never the harness's), and a runtime that cannot apply it refuses the
  session rather than dropping it (podman). No extension publishes ports, joins
  the harness network, mounts the docker socket, or binds host paths other
  than its own session state and, for a trusted extension and a setting the
  user chose, a named subdirectory of `work/` (never all of it).
- **The harness** only ever gets forwarders on its internal network.
- **Harness mounts** from an extension (`mounts: {models: {setting: models_dir}}`)
  are read-only binds at `/mnt/<ext>-<name>` of a directory the user named in a
  `path` setting (such a setting may not have a default), checked like the
  session's own `mounts:` (never `.glove/`, `local/`, the session file, glove's
  home or another session's state).
- **Harness contributions** are harness-neutral where they can be, under
  `harness:` — `env`, `image` (`"*"` or per harness), `brief`, and:
  - `mcp: [{name, transport: stdio|http, …, tools: [...]}]`: an MCP server,
    rendered by harnesses that speak MCP (Vibe: `config.toml`, with `tools`
    as an allowlist);
  - `skills: [skills/x]`: a `SKILL.md` directory baked into the image, or one
    from a mount (`{mount: m, path: skills/y}`, skipped when that mount is off),
    for harnesses that load skills (Pi: `settings.json`);
  - `<harness>: {...}`: a section only that harness's adapter reads, e.g.
    `pi: {extensions: [pi-extension]}` (Pi has no MCP, so it loads its own
    code with `pi -e`).

  Any other key is an error.
- **Out-of-tree** extensions load from `extension_paths:` in
  `~/.glove/config.yml`, are labelled *out-of-tree*, and cannot take privilege
  exceptions (or reach host ports) unless listed in `trusted_extensions:`.

`llm` is the inference engine, picked like a gluetun VPN provider: `provider:`
names a catalog entry (`extensions/llm/providers/*.yml`). `location:` routes it:
`host` → a forwarder to this Mac; `lan` → a forwarder that dials exactly the
configured `host:port`; `internet` → a forwarder to the provider's HTTPS host,
aliased so TLS runs end to end. The harness never gets LAN or internet reach
itself. `model: auto` and `capabilities: auto` are resolved at launch from a
throwaway container on the harness network (the host never contacts the
server), and the harness's adapter renders the result into its own config
(Pi `models.json`, Vibe `config.toml`; vision → `input: ["text","image"]`).

### Egress: `vpn`, `tor`, `direct`, `corporate`

Web tools reach the network only through the session's **egress provider**,
one of `vpn` (a [gluetun](https://github.com/qdm12/gluetun) tunnel), `tor`
(tor + privoxy), `direct` (a plain proxy, no anonymity) or `corporate`
(corporate resources only, over this machine's corporate VPN). Each session gets
its own networks:

| Network | Kind | Who joins |
|---|---|---|
| `glove-<id>-net` | internal | the harness and its forwarders |
| `glove-<id>-egress` | internal | egress consumers (SearXNG, the `proxy` forwarder, observe's gates) and the provider's proxy |
| `glove-<id>-wan` | bridge | **only** the egress provider's tunnel container |

So only the tunnel container can reach the internet. If its proxy fails,
consumers have no other route out (egress fails closed by topology).

Before the harness starts, `glove up` runs each extension's **verify** checks:
`container-healthy`, `tcp-open`, `http-ok`, `http-refused` and
`exit-ip-differs`. `exit-ip-differs` requires the exit IP seen through the proxy
to differ from this machine's IP, and fails if either is unknown;
`http-refused` requires the proxy to refuse a URL (corporate: the general
internet). They run from throwaway hardened containers on
the session's networks. A failing check shows the sidecar's last log lines (key
and password lines withheld) and stops the session's sidecars. VPN secrets are
Keychain references handed to gluetun as compose secrets. An optional
**register hook** in the session's `local/` can mint a fresh WireGuard key at
every `glove up` (see [extensions/vpn/README.md](extensions/vpn/README.md)).

`search` runs SearXNG and valkey in the session, with every engine request
going through the egress proxy. `webfetch` gives Pi `web_fetch` through a
`proxy` forwarder. Both need an egress provider. The `pi-search` template puts
it together: `glove new pi-search <dir>`.

**`corporate`** is a netgate proxy that resolves and dials destinations itself
(`dns: host` follows the VPN's split DNS through Docker Desktop / Podman
machine) under a static **default-block** policy: only `allow_domains` (host
globs), `allow_cidrs`, and with `from_interface: utun4` the host's routes via
that interface (read from `netstat -rn` at plan time, shown in `glove plan`,
stored in `.glove/effective.yml`). Those entries are also its SSRF-guard
exceptions, because corporate hosts are private; they come only from
`glove-session.yml`, never from `rules.json`. This machine, the runtime's host
gateway, cloud metadata and the session's own network stay refused even inside
an allowed range. `tcp: [{name: git-ssh, to: "git.example.internal:22"}]` adds
raw TCP endpoints (`glove-<id>-git-ssh:22`). `glove up` checks that
`https://example.com` is refused through it, and that `probe_url` (if set)
answers. Template: `glove new corporate <dir>`; details in
[extensions/corporate/README.md](extensions/corporate/README.md).

### Network observability: `observe` (read) and `filter` (write)

Two explicit, per-session grants, each its own extension:

| Grant | Extension | What it does |
|---|---|---|
| **observe** | `observe` | every forwarder becomes a recording **netgate**; flows (and, by default, the harness's transcripts) are exported to `~/.glove/observe/<id>/` |
| **filter** | `filter` (needs `observe`) | `~/.glove/control/<id>/rules.json` exists and every gate enforces it; `glove filter …` and Layman edit it |

```yaml
extensions:
  observe:
    record: metadata          # metadata | full (method + URL of cleartext HTTP; loud warning)
    resolve: in-tunnel        # in-tunnel | none — there is deliberately no `host`
    exit_identity: none       # via-proxy: poll the apparent exit IP through the tunnel
    transcripts: true         # export the harness transcripts too
    rotate_mb: 64             # rotate flows.ndjson at this size…
    keep: 8                   # …keeping this many rotated files
    retain: none              # e.g. 12h: expire older records
    skip: []                  # endpoint names that stay plain socat
  filter: {}
```

**observe** fills the `forwarder` slot: each endpoint's forwarder is a netgate
instead of socat, a drop-in (same container name, networks and port, so the
harness config is unchanged) that records every connection: open, ~1 Hz updates
while bytes move, and close, with cumulative byte counts, timing, tool label and
scope. Records go to `~/.glove/observe/<id>/net/` through a single collector
container that has **no network at all** (`network_mode: none`):

```
net/session.json    static facts: services, tools, upstreams, record mode, grants (0600)
net/flows.ndjson    append-only flow stream + gate start/stop records, size-rotated
                    to flows-<stamp>[-<n>].ndjson (order by (stamp, n), not by name)
net/exit.ndjson     apparent-origin changes (only with exit_identity: via-proxy)
net/status.json     gate heartbeat, upstream health, dropped-record counters, and —
                    only with filter — the rules load result (the enforced file's SHA-256)
```

With `transcripts: true`, glove binds `~/.glove/observe/<id>/transcripts/` over
the harness's transcript directory (Pi `.pi/agent/sessions`, Vibe
`.vibe/logs/session`), so transcripts are written there directly; `glove up
--resume` finds them there too.

**Proxy gates.** A forwarder to the egress proxy (`webfetch`'s `proxy`) runs in
`http-proxy` mode: it reads the destination from each `CONNECT host:port` or
`GET http://host/…`, records the real hostname, and chains to the egress proxy
**by hostname**, so the tunnel, not the gate or your host, resolves it. The
route (`vpn|tor|direct|corporate`) comes from the egress provider. Before
anything goes upstream, a built-in **SSRF guard** refuses non-public
destinations (private and metadata IPs in any notation, container names,
`.internal`/`localhost` names), recorded as blocked flows. With the egress
provider's in-tunnel resolver (gluetun's DNS, Tor's SOCKS `RESOLVE`), flows
carry `dest.ip` with `resolution: in-tunnel`, `ip` rules apply to hostnames,
and a name that resolves to a private address is refused. `tcp`-mode gates
peek (never terminate) a TLS ClientHello, so an HTTPS flow shows its SNI.

**The whole chain.** With observe on, **SearXNG leaves the egress network**:
its engine requests go through its own gate (`searxng-egress`, `client:
searxng`) on the search extension's private network, the only route it has to
the egress proxy. One `web_search` shows every engine SearXNG contacted.

**filter** mounts `control/<id>/` read-only into every gate and the collector
and passes `--rules`. `glove filter block '*.doubleclick.net'` writes a rule to
`rules.json`, the same file Layman writes. The gates reload it within about a
second, refuse new matching connections with a recorded `verdict: block` (and
`web_fetch` tells the agent it was refused by policy, with the reason), and with
`--terminate` also cut established ones. A malformed or unreadable file is
rejected as a whole: the gates keep the previous rules and report the error in
`glove filter rules` and `status.json`. `glove filter validate FILE` runs the
gate's validator without a gate. **Observe alone never mounts `control/`,
never passes `--rules`, and glove never creates `control/<id>/` for it.**
Removing `filter:` revokes the grant at the next `glove up`: `rules.json` moves
to `.glove/ext/filter/rules.revoked.json`, `control/<id>/` is removed, and
`grants.filter.granted` becomes `false`. The built-in SSRF guard always runs
first; `rules.json` cannot widen it.

Guarantees, each covered by tests (`extensions/gate/tests/`,
`extensions/observe/tests/`) and live runs (`tests/integration/test_observe.sh`,
`test_netgate_shutdown.sh`, `netgate_control_perms.sh`, on Docker and Podman):
- the gates expose no API on any network, never gain `NET_ADMIN`, join the
  harness's network or PID namespace, or mount the harness home;
- `net/` and `control/` have no harness mount, and a render that would expose
  them is refused (not waivable);
- nothing resolves a destination hostname on the host;
- telemetry failures drop records, never traffic.

**Gate lifecycle.** Every flow record carries its forwarder's `run` id, and
`flows.ndjson` records each forwarder's and the collector's `start`/`stop`. A
clean `glove down` stops the forwarders before the collector, so every open
flow gets its `gate_shutdown` close. A forwarder that dies without one gets an
inferred `stop` from the collector after 30 s of silence, and `glove observe
status` counts its unclosed flows as cut, not active. `glove down --wipe`
deletes the flow record (not `session.json` or transcripts).

Sample data: `tests/fixtures/netobs/` (the v2 fixture, frozen),
`tests/fixtures/netobs-scenarios/` (one directory per flow state) and
`tests/fixtures/netobs-v3/` (one `~/.glove` tree per grant state, generated by
`extensions/observe/tests/fixtures/generate.py`). On Podman, sidecar binds are
labelled `selinux: z`, tmpfs volumes get a container SELinux context when
SELinux is on, and sidecars start one at a time (see
[docs/SECURITY.md](docs/SECURITY.md)). Rootful Docker on Linux: **untested**.

### Layman

[Layman](https://github.com/castellotti/layman) shows glove's
sessions and traffic, and edits their rules. The two projects are independent:
Layman touches glove's folders only if they already exist, and glove owns
every folder, owner and mode under `~/.glove`.

- **What Layman mounts.** `~/.glove` read-only, and `~/.glove/control`
  read-write over it, each only if it exists when Layman starts. Layman follows `~/.glove` only, not
  `$GLOVE_HOME`. A `control/` that appears later is picked up when Layman
  restarts.
- **What glove guarantees.** Whenever glove creates its home (`glove new`, any
  registry write), it also creates `control/`, and adds it to an older home
  that lacks it. Both are yours, mode `0777 & ~umask` (`0755` usually).
  `observe/<id>/` exists only with the **observe** grant (`net/` is `0700`,
  files `0600`), and `control/<id>/` (`0700`) only with the **filter** grant;
  both grants are in `session.json` and the registry row. `rules.json`'s `env`
  and `session` are both the session id. glove warns, with the `sudo chown`
  that fixes it, when `control/` belongs to someone else. Layman's side of the
  v3 paths are documented in the Layman repository.
- **What Layman writes.** Only `control/<id>/rules.json`, only if
  that directory exists, and by atomic rename: a temp file unique to Layman
  in the same directory, `fsync`, `chmod 0644` (explicitly, not through the
  umask), rename. No `chown`, no new directories. The directory is `0700` and
  yours, so the file is readable by the gate (which runs as you) and by nobody
  else. The contract is the handoff's §3, "Ownership".
- **SELinux hosts (Fedora, RHEL) are not supported yet**, for glove sessions
  or for Layman. On an enforcing host a container is denied files under your
  home unless they carry a container label, and glove sets none on its home or
  on `/work`. Supporting it is a separate piece of work that must decide how
  harness homes are isolated from each other and what Layman may read.

Verified by `netgate_control_perms.sh` on Docker Desktop and on rootless and
rootful Podman.

### Documents: `ocr`, `rag`

**`ocr`** bakes tesseract (plus the `languages:` packs you pick), ocrmypdf,
poppler, ghostscript and `file` into the harness image, with a small
`glove-ocr FILE` command: an image's text, or a PDF page by page (the text
layer where there is one, OCR where not; `--pages`, `--lang`, `--json`). There
is no model-vision mode: a shell command has no network, so it cannot call the
session's model. A model with vision looks at images itself, and the brief says
which applies.

**`rag`** (requires `ocr`) bakes kstore: `kstore sync` turns
`/work/data/input` into a keyword (Obsidian vault) and a vector (FAISS) store,
OCR'ing scans and images, and `kstore ask` retrieves passages with citations
(file, page, char/line) back to the original. Pi gets the `rag-parse` and
`rag-query` skills. Embeddings run in-process (fastembed) from `models_dir`, a
read-only mount filled once by `glove rag fetch-model`; `obsidian_dir` (a
claude-obsidian checkout, read-only) adds its vault-synthesis skills. No egress
provider is needed. Template: `glove new pi-rag <dir>`; details in
[extensions/rag/README.md](extensions/rag/README.md).

### Browser: `playwright`

A real Chromium through Playwright's MCP (`playwright-core@1.63.0 mcp`, pinned
by lockfile). **`headless`** (default) and **`novnc`** run it in a hardened
sidecar that sits alone on an internal network with two forwarders: the
harness's way in (`browser`) and the browser's way out (`browser-egress`, to
the session's egress proxy; with `observe`, a gate that records every
destination as `client: playwright` and applies `filter` rules and the SSRF
guard). Chromium's own sandbox is on, with the sidecar-only `chromium-userns`
seccomp profile (on Podman set `chromium_sandbox: "off"`). In `novnc` mode it
runs headed on a VNC display inside the sidecar; `glove playwright view` opens
it in your browser through a loopback tunnel that lives only while the command
runs, view-only unless `allow_control: true` (enforced by the VNC server).
**`host`** drives a Chrome on your desktop (refused behind vpn/tor). The agent
gets only the `tools` allowlist: Pi registers just those, Vibe hides every
other `playwright_*` tool (`browser_run_code_unsafe` included). A private CA
for the sidecar is `playwright: {ca: <pem>}`. It is set separately from
`corporate_ca`, so set both when the browser is used. The sidecar's Node trusts it
through `NODE_EXTRA_CA_CERTS` and Chromium through an NSS import. Template:
`glove new browse-watch <dir>`; details in
[extensions/playwright/README.md](extensions/playwright/README.md).

## How it works - three rings (defense in depth)

The agent and everything it spawns are treated as **untrusted** (the real threat
is prompt injection making the model run a bad command). Three independent rings
must each be defeated:

- **Ring 0 - Runtime** (container/VM): namespace, a bind-mount **allow-list**,
  an **internal-only network** (only single-purpose forwarder sidecars are
  routable), and a non-negotiable hardening set - non-root, `cap_drop ALL`,
  `no-new-privileges`, read-only rootfs, seccomp, pids/mem/ipc limits. Never
  `docker.sock`, never `--privileged`, never host-gateway on the harness.
- **Ring 1 - Enforcer** (kernel policy on every process): **nono+srt**
  (default on Docker) puts srt (bubblewrap) around the harness and nono
  (Landlock) around every shell command; **nono** (default on Podman) wraps the
  harness *and* every shell command with Landlock alone; **srt** (opt-in) wraps
  shell commands only. A prompt-injected
  command can only write `/work` + exposed rw dirs, cannot read the harness
  home / secrets, has **no network** and no terminal to type into the harness.
- **Ring 2 - Harness integration**: a Pi extension / Vibe `pre_tool` hook routes
  every `bash`/`!` command through ring 1 and blocks egress tools; a generated
  context file tells the agent the rules.

See **[docs/SECURITY.md](docs/SECURITY.md)** for the full threat model and the
Docker Desktop macOS blast-radius explanation.

### Enforcer: `nono+srt` (the default on Docker)

```yaml
enforcer: nono+srt    # what a session gets on Docker when it names no enforcer; `nono` on Podman
```

```
glove-pty relay -- glove-srt srt-harness.json -- glove-pty ctty -- pi …
  every shell command: glove-pty notty -- nono wrap --profile tool.json -- bash -c <cmd>
```

srt (bubblewrap) wraps the harness process, nono (Landlock) wraps every shell
command inside it. What that adds over `nono`:

- **Deny-inside-allow writes.** `/work` is writable, but `.git/hooks`,
  `.git/config`, `.vscode`, `.idea`, `.envrc`, `.mcp.json`, `.gitmodules` and
  `.claude/{commands,agents,settings*.json}` are read-only for the harness and
  its commands (those present at launch; protecting a missing one would put
  an empty placeholder file in your `work/`), plus srt's own list of shell rc
  and git files where they exist.
- **`.env` and `.env.*` under /work are hidden** from the harness and its
  tools (files present at launch; `enforcer_options: {srt: {hide_env: false}}`
  turns it off).
- **No namespaces, mounts, AF_UNIX sockets or io_uring** for the harness or
  any command: glove builds srt's `apply-seccomp` with its own filter, so only
  srt itself can use what the relaxed container profile opens. The harness and
  its commands also get their own PID namespace.
- **Two kernel mechanisms** (bubblewrap + Landlock) between a command and the
  container.

The harness keeps the container network, which ring 0 already limits to the
session's forwarders; srt's own network confinement would only repeat that and
breaks clients with their own proxy (web_fetch). srt's CLI always confines the
network, so glove runs srt's library through a small launcher (`glove-srt`).
The TUI runs on a pty glove relays (srt starts it without a controlling
terminal), so resize and Ctrl-C work.

Costs: the harness container runs under the relaxed `nested-userns` seccomp
profile (like `srt`); the harness starts ~0.1 s slower; the image is
`<harness image>-srt-<hash>` (srt, bubblewrap and its own Node layered on).
Refused on podman: its compose provider can't apply the profile.

## Support matrix

| Component | Option | Status |
|---|---|---|
| Runtime | docker | hardened + doctor probes |
| Runtime | podman | hardened + doctor probes; v3 session dirs verified live on Podman Desktop (macOS, podman 6.1.2 rootless, applehv, Landlock ABI 9): session lifecycle 10/10, nono Pi 19/19, Vibe 13/13, ring-0 15/15; srt and nono+srt are refused on podman. Runs alongside Docker Desktop (each runtime has its own VM, image store and networks) |
| Runtime | apple-container / gondolin / utm | stub (registered, `NotImplementedError`) |
| Enforcer | nono (Landlock) - default on podman | nono 0.78.0; Pi wired + verified (19-check integration), Vibe (13) |
| Enforcer | nono+srt - default on docker | srt wraps the harness (deny-inside-allow writes, `.env` hidden, no namespaces/mounts below it), nono every command; verified live on Docker with Pi and Vibe (29 checks each: `test_nono_srt.sh`) and under every extension suite (egress, observe, playwright, corporate); refused on podman |
| Enforcer | srt (bubblewrap) - opt-in | srt 0.0.77 with glove's `apply-seccomp`; Pi wired + verified (12-check integration, incl. env/`/proc` key leaks, no user namespaces); tool commands only; Vibe untested |
| Enforcer | none (ring 0 only) | debug |
| Inference | `llm` extension: openai-compatible (default; vLLM, NInfer, …), llama.cpp, ollama, lmstudio, openai, anthropic, mistral, openrouter | `host` verified live (stub llama-server); `lan` verified live (`openai-compatible` → NInfer over the user's VPN, `model: auto`, key by Keychain reference, Pi answered); cloud providers **untested** |
| Egress | `vpn` (gluetun, WireGuard/OpenVPN, optional register hook) | verified live on Docker and Podman (WireGuard through a register hook, keys from the Keychain: tunnel healthy, exit ≠ host, search and web_fetch through the tunnel; with `observe`: flows `route: vpn`, destinations resolved in-tunnel by gluetun's DNS; also under `nono+srt` on Docker); OpenVPN and built-in gluetun providers **untested** |
| Egress | `tor` (tor + privoxy), `direct` (tinyproxy) | verified live on Docker and Podman: `exit-ip-differs` (tor), only the provider on `wan`, SearXNG and the harness network have no direct internet, Pi `web_search`/`web_fetch` through the egress; two sessions concurrently |
| Egress | `corporate` (a default-block netgate proxy + allowlist) | verified live on Docker and Podman with a public host standing in for a corporate one (allowed host reached, everything else refused with the gate's reason, host gateway/metadata/own network refused even inside an allowed CIDR, raw TCP endpoint); **through a real corporate VPN: untested** (the operator runs it) |
| Observability | `observe` (read) + `filter` (write) | verified live on Docker and Podman (direct and tor): every forwarder a netgate, flows for the harness's tools and SearXNG's engines, in-tunnel resolution over Tor, transcripts exported, `glove filter block` enforced and confirmed by SHA-256, revocation; `netgate_control_perms.sh` 6/6 and `test_netgate_shutdown.sh` 9/9 on both |
| Documents | `ocr` (tesseract/ocrmypdf/poppler + `glove-ocr`), `rag` (kstore: Obsidian vault + FAISS, fastembed in-process) | verified live with Pi on Docker and Podman: `glove-ocr` on a PNG, a scanned PDF page and a text-layer PDF; `kstore sync` (scan and image OCR'd, index built from the read-only model mount, offline) and `kstore ask` citing the original scanned page, all as Pi `bash` tool calls in the nono tool sandbox; rag and claude-obsidian skills in Pi's prompt. **Vibe: untested** (kstore via uv, no skills) |
| Browser | `playwright` `headless` / `novnc` sidecars | verified live with Pi and Vibe on Docker (sandbox on) and Podman (`chromium_sandbox: "off"`: podman compose cannot apply the `chromium-userns` seccomp profile, and glove refuses rather than dropping it): no ports, no capabilities, only on an internal network with no DNS or route; browsing through the egress; flows `client: playwright`, `glove filter` and the SSRF guard enforced at the gate; the agent offered only the allowlisted tools; `glove playwright view` loopback-only with Host/Origin checks; view-only and clipboard-off enforced by the VNC server (an RFB click lands only with `allow_control` and the full password). Behind vpn/tor/corporate: **untested** (direct egress only) |
| Browser | `playwright` `mode: host` | implemented; MCP pinned (`playwright-core@1.63.0 mcp`); per-session Chrome profile and ports; refused behind vpn/tor, and with Vibe unless `i_accept_host_rce: true`; host-side start **untested** |

The sidecar modes need nothing on the host. Host mode needs Node/npx and a
Chromium-family browser on the host; the friction-free option is Playwright's
own Chrome for Testing (`npx playwright install chromium`). For a complete,
reproducible host-mode setup - Pi
against a remote OpenAI-compatible LLM over an SSH tunnel plus a dedicated headed
Playwright browser, including the `@playwright/mcp` `--browser` channel gotcha and
the `--executable-path` fix - see **[docs/pi-remote-llm.md](docs/pi-remote-llm.md)**
and start from **[docs/examples/pi-remote-llm.glove-session.yml](docs/examples/pi-remote-llm.glove-session.yml)**
(`glove new docs/examples/pi-remote-llm.glove-session.yml <dir>`).

Runnable presets live in **[docs/examples/](docs/examples/)**.

## Upgrading from v2

v3 is a clean break: there is no automatic migration, and glove refuses v2
state rather than guessing.

- **Environments became session directories.** `glove init/run`, `--name`,
  `~/.glove/envs/` and `~/.glove/homes/` are gone. Create a session with
  `glove new <template> <dir>` and copy the old values into its
  `glove-session.yml`. A v2 `~/.glove/registry.json` is refused; move it aside.
- **Old keys are refused with a pointer:** `model`/`llm_service`/`llm_api_key`/
  `host_gateway` → `extensions.llm`; `services`/`net`/`observe` →
  `extensions.search`/`webfetch`/`observe`/`filter`; `workdir`/`add_dirs` →
  `work/` + `mounts:`.
- **Template repos became bundled templates** (`templates/`). A v2 instance's
  `.env` values map as follows: the LLM host/port/model/Keychain service →
  `extensions.llm`; VPN Keychain services and the register hook →
  `extensions.vpn` (`provider: custom`, the hook copied into `local/`);
  `egress/.env` `GROUP_*`/`ENGINE_*` → `extensions.search.groups`/`engines`;
  the network-observability switches → `extensions.observe`.
- **Transcripts:** move `~/.glove/homes/<env>/.pi/agent/sessions/*` into the
  new session's `.glove/home/.pi/agent/sessions/` (with `observe`'s
  `transcripts: true`: `~/.glove/observe/<id>/transcripts/`, created by the
  first `glove up`) to keep resuming them.
- **Enforcer:** a session that names none now gets `nono+srt` on Docker.

## Toolchain

Python ≥ 3.11 managed with [uv](https://docs.astral.sh/uv/):

```sh
uv sync
uv run ruff check glove extensions tests   # lint
uv run pytest -q                           # unit suite (includes the layering check)
uv run lint-imports                        # core (glove/) must not import extensions/
# integration (need Docker; build the images first):
bash tests/integration/test_pi_nono.sh    # nono / Pi  (19 checks)
bash tests/integration/test_vibe_nono.sh  # nono / Vibe (13 checks)
bash tests/integration/test_pi_srt.sh     # srt  / Pi  (12 checks)
bash tests/integration/test_nono_srt.sh pi    # nono+srt in a real session (29 checks; also: vibe)
bash tests/integration/test_ring0_protect.sh  # ring-0 ro binds over .git/hooks etc. (15 checks)
bash tests/integration/test_session_dir.sh    # session dir lifecycle vs a stub llm (10 checks)
bash tests/integration/test_egress.sh tor     # egress + search + webfetch end to end (also: direct;
                                              # vpn with VPN_SETTINGS=… [VPN_LOCAL=<hook dir>]) (11 checks)
bash tests/integration/test_observe.sh direct # observe + filter end to end (also: tor) (25/26 checks)
bash tests/integration/test_corporate.sh      # corporate egress, a public host as stand-in (11 checks)
bash tests/integration/test_netgate_shutdown.sh   # clean down / killed forwarder records (9 checks)
bash tests/integration/netgate_control_perms.sh   # who can read/write net/ and rules.json (6 checks)
bash tests/integration/test_toolchains.sh     # pinned node/python + deps + Chromium, offline (35 checks)
# RT=podman runs every script above except test_pi_srt on Podman (test_nono_srt checks the refusal)
# (images are per runtime: `glove build pi --provider podman`)
bash tests/integration/test_llm_host_stub.sh  # llm location: host vs a stub llama-server, Pi answers
bash tests/integration/test_llm_lan.sh HOST:PORT [KEYCHAIN_SERVICE]  # llm location: lan vs your server
```

The core in `glove/` is kept minimal (about 8.5k lines of Python); in-tree
extensions live in `extensions/`, templates in `templates/`. The import boundary is enforced by
[import-linter](https://import-linter.readthedocs.io/): `glove` must never import
`extensions`, the same way a kernel never depends on its modules.
