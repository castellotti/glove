# glove

`glove` is an AI **sandbox** that launches an agentic coding harness (Pi, Claude Code, 
Mistral Vibe, etc.) and is distributed and managed inside containers (Docker or Podman).
Interface to the user is via a Python CLI, which presents the harness's normal TUI
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
sandbox (Anthropic's **sandbox-runtime**, aka "[srt](https://github.com/anthropics/sandbox-runtime)"/[bubblewrap](https://github.com/containers/bubblewrap) around the harness and [nono](https://github.com/nolabs-ai/nono)/Landlock around every
command on Docker; [nono](https://github.com/nolabs-ai/nono) alone on Podman) runs *inside* the container and wraps
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
per-session [SearXNG](https://github.com/searxng/searxng)), **`webfetch`** (read a page through the egress), **`observe`** (network
observability, read) and **`filter`** (network rules, write), **`media`**
(analysis toolchain), **`toolchains`** (pinned Node/Python and a project's
dependencies, baked at build time), **`ocr`**/**`rag`** (documents), **`playwright`** (a
real Chromium: a hardened headless sidecar, a noVNC-watched one, or the host's
Chrome), **`github`** (`gh` and `git push` from shell commands, relayed to a
sidecar that holds the token) and **`ssh`** (`ssh <host> <command>` to named LAN
hosts, relayed to a sidecar that holds the key). See [Extensions](#extensions).

## Quick start

glove runs from a checkout (the bundled `harnesses/`, `extensions/`, `commands/` and `templates/` live
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
glove check                             # schema, secrets exist (never read), doctor, the LLM server answers
glove plan                              # what it grants; renders .glove/, launches nothing
glove up                                # build → sidecars → resolve model → TUI
glove down                              # stop (glove rm: also delete .glove/)
```

`glove new` takes a bundled template (`templates/`: `minimal`, `pi-search`, `pi-rag`, `browse-watch`, `corporate`, `claude-code`, `vibe-search`), a path to a
directory or file, or a git URL. Templates are *materialized*, not inherited:
the file is a full copy, so upgrading glove never silently widens a session.
`glove check` warns when the template changed since, and `glove new --diff`
shows how.

```
<session-dir>/
  glove-session.yml   the file you edit (no secrets: references only)
  work/               → /work (rw)
  local/              optional private host assets (e.g. hooks); never mounted
  skills/             optional plugin and skill checkouts (the `skills`
                      extension bakes a checked copy); never mounted
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
| `claude-code` | Claude Code on an Anthropic subscription, for software work | `llm` (`auth: oauth`), `direct`, `webfetch`, `playwright`, `github`, `observe`, `filter`; Python/Node toolchains, Playwright's Chromium usable from shell commands |
| `vibe-search` | `pi-search` with Mistral Vibe as the harness | as `pi-search` |

Each has a `README.md` in `templates/<name>/`. A template's private parts
(Keychain service names, VPN register hooks, local model paths) never live in
the template: `glove-session.yml` holds `keychain:<service>` references and
paths you fill in, and hooks go in the session's `local/`. A template of your
own (a directory path or git URL) may carry a `local/`: `glove new` copies it
into the session, never over a file already there (regular files only, no
symlinks).

## Session file (`glove-session.yml`, schema v3)

```yaml
glove: 3
template: minimal           # provenance only
harness: pi                 # pi | vibe | claude-code
runtime: docker             # docker | podman | apple-container|gondolin|utm (stub)
enforcer: nono+srt          # default: nono+srt on docker, nono on podman | nono | srt | none
mounts:                     # explicit extra host dirs; work/ is always /work
  - { path: ~/src/shared-lib, mode: ro }
extensions:                 # name → settings; unlisted = nothing in the session
  llm:                      # required: fills the `inference` slot
    provider: llama.cpp     # openai-compatible (any OpenAI-API server) | anthropic-compatible | llama.cpp | ollama | lmstudio | openai | anthropic | mistral | openrouter
    location: host          # host (this Mac) | lan | internet
    endpoint: 127.0.0.1:8080
    model: auto             # or an id; auto = the single model /v1/models lists
    capabilities: auto      # or explicit keys, e.g. {vision: true}; probes fill the rest
    # api_key: keychain:my-llm   # a reference only (keychain:<service> | env:<VAR>)
  vpn:                      # egress: exactly one of vpn | tor | direct
    provider: <set-me>      # a gluetun provider name, or custom
    wireguard_key: keychain:my-vpn-wg
  search: {}                # per-session SearXNG behind the egress
  webfetch: {}              # read a page through the egress (Pi web_fetch, Claude Code WebFetch, Vibe fetch_url); {downloads: work} adds web_download
  media: {}
  # playwright: {}           # a real Chromium in a sidecar, via the egress (mode: headless | novnc | host)
  # github: { token: keychain:my-github }   # gh / git push from shell commands; the token stays in a sidecar
  #   (GitHub Enterprise: hosts: [{host: <name>, token: keychain:<service>}]; read-only git: git: [fetch, clone, ls-remote])
  # ssh: { key: keychain:my-ssh, hosts: [{name: build, to: "build.lan:22", user: me}], known_hosts: local/known_hosts }
  observe: {}               # network observability (read) — see below
  # filter: {}              # network rules (write); needs observe
tools: { allow_commands: [cp, mv, rm] }   # nono's tool policy (nono, nono+srt only): allow_commands, deny_commands; unknown keys are refused
limits: { pids: 512, memory: 4g, cpus: 2 }
enforcer_options: { srt: { nested: weak } }   # nono+srt also: hide_env (default true); nono / nono+srt: nono: { browsers: true }; unknown keys are refused
protect_ide_files: false    # also ro-bind .vscode/.envrc/.mcp.json (creates empty ones if missing)
# git_config: { safe.directory: "*" }      # added to git's config in the harness (see "git in /work")
# allow_root: true          # the harness as uid 0; caps stay dropped and no-new-privileges holds, so no sudo
# corporate_ca: local/corporate-ca.pem   # a private CA the harness trusts too (see below)
```

Relative mount paths resolve against the session directory. A mount that would
expose `.glove/`, `local/`, `skills/`, `glove-session.yml`, glove's home (`~/.glove`) or
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
`/etc/glove`, so no policy changes. That covers Node (Pi, Claude Code,
`web_fetch`). For everything else (curl, git, gh, Python `requests`/`urllib`,
Vibe's client), glove bakes `/etc/glove/ca-bundle.pem` into the session's derived
image: the image's own roots, then the CA. It sets `SSL_CERT_FILE`,
`REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `GIT_SSL_CAINFO` to that path, each only
if `env:` doesn't set it. Changing the PEM rebuilds the image on the next `up`.
The `github` relay and `webfetch`'s fetcher trust the CA too: core binds the same
file read-only into them (`trust:` in their manifests), and they build
the same kind of bundle in their own `/tmp`. The browser
sidecar is configured separately: set `playwright: {ca: …}` as well (see Browser
below). Unset, nothing renders differently.

**Language toolchains (the `toolchains` extension, off by default).** Pinned
Node/Python runtimes, a project's lockfile-strict dependencies and Playwright's
browsers, baked into the image at build time (shell commands are offline):
`extensions: {toolchains: {blocks: [{lang: node, version: "22.23.3", project:
projects/web}]}}`. See [extensions/toolchains/README.md](extensions/toolchains/README.md).

Each session gets a /24 from `subnet_pool` in `~/.glove/config.yml` (default
`172.31.0.0/16`), recorded in the registry, and each of its networks a /27 of
it. Allocation avoids other sessions and the runtime's existing networks; if a
foreign network takes the range later, `glove up` re-allocates. If one takes
it between the check and `compose up` (another session starting at the same
moment), `glove up` says so, re-allocates and retries (3 attempts).

`.git/hooks` and `.git/config` in every rw mount are always bound read-only (and
`.git` is pinned so it can't be renamed away): an agent must not plant a hook your
Mac runs the next time you use git. See "Planted host-trusted files" in
[docs/SECURITY.md](docs/SECURITY.md).

## CLI

Session commands take an optional directory; without one they use the nearest
`glove-session.yml` at or above the current directory. Every command lives in
`commands/<name>/` ([commands/README.md](commands/README.md)); core only mounts them.

```
glove new <template|path|git-url> [DIR]      # materialize a session (DIR default: .)
glove new --diff <any> [DIR]                 # how the template changed since `glove new`
glove check [DIR] [--no-container] [--offline]   # schema, placeholders, secrets exist, doctor; the LLM
                                             # server lists the model, asked from a throwaway container
                                             # (--offline: contact nothing)
glove plan  [DIR] [--compose] [--resume|--session ID]   # render .glove/, print the grants
glove up    [DIR] [--resume|-r] [--session ID] [--rebuild]   # runs the extensions' checks first
glove down  [DIR] [--wipe]                   # --wipe: also volumes + the flow record
glove rm    [DIR] [--all] [--yes]            # down --wipe, delete .glove/ + exports + row
glove policy [DIR]                           # ring-1 policies + ring-0 hardening + gaps
glove ls | ps | gc [--yes]                   # registry rows (ok|missing|stale), running, prune
glove clean [--dry-run] [--yes] [--runtime R]   # remove dead sessions' stacks on Docker/Podman
glove keychain set <service> [--stdin]       # store a secret, prompting or piped (never in argv; a long
                                             # one in parts, <service>.part<n>; ASCII only)
glove downloads mark [DIR]                   # macOS: quarantine new files the sidecars saved (down does too)
glove doctor [--runtime R] [--enforcer E] [--json] | build [HARNESS] [--enforcer srt|nono+srt] | version
glove ext                                    # every loadable extension, origin, CLI
glove observe status [--dir D] [--json]      # (observe) gate health + per-service totals
glove observe flows  [--dir D] [--follow] [--json] [--tail N]
glove filter block  <host-glob|ip|cidr> [--port N] [--terminate] [--allow] [--note TEXT]
glove filter unblock <rule-id|target>        # (filter) only with the filter grant
glove filter rules  [--json]                 # rules + the gates' load result
glove filter validate <file|-> [--env ID] [--session ID] [--json]   # the gate's validator; pure
glove playwright view [--dir D] [--control] [--no-open]   # (playwright novnc) watch/drive the browser
glove playwright status [--dir D]            # also the stored session's first cookie expiry
glove playwright login  [--dir D] [--keep-profile] [--no-reload]   # sign in with a dedicated host Chrome;
                                             # the session and captures to the Keychain
glove playwright reload [--dir D]            # recreate the browser sidecar from the stored session
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
> that the Keychain item exists, and asks the server for its models without the
> key), and the effective config records
> only the reference. **The harness never holds an API key:** glove hands it
> only to the `llm` extension's `llm-auth` sidecar (through `compose`'s
> environment at launch), which adds it to model requests and refuses anything
> but the model API's paths ([extensions/llm/README.md](extensions/llm/README.md)).
> The harness's variable (`GLOVE_LLM_API_KEY`; Claude Code's
> `ANTHROPIC_API_KEY`) holds the public placeholder `glove-injected`. A Claude
> Code subscription token (`auth: oauth`, below) is held the same way. Store a
> key with `glove keychain set <service>` (it prompts; the key is never in
> argv).

## Harnesses

A harness is a directory under `harnesses/`, beside `extensions/`:

```
harnesses/<name>/
  harness.yml    # the profile (data): image tag, release (`version`, `audited_version`),
                 # TUI entry, config home, context file, `brief`, transcript dirs,
                 # resume flags, which neutral contributions it renders
  brief.md       # what the agent is told about this harness under glove (optional)
  adapter.py     # renders its native config; may add entry args / image lines (optional)
  image/         # the base image's build context (Dockerfile, ring-1 glue)
  tests/
```

Core reads every `harness.yml` and imports `adapter.py` by path only for the
harness a session selects. Every image bakes the one shared entrypoint
(`glove/enforcers/entrypoint`, the `gloveentry` build context) that validates the
ring-1 policies before the harness starts. Bundled: `pi`, `vibe`, and
`claude-code`. The names are stable: `~/.glove/registry.json`
and observe's `session.json` record them, and external monitors (Layman) pick a
transcript parser by them.

Each manifest pins the harness release its image installs (`version`, passed
to the build as `HARNESS_VERSION`; Pi 1.1.0, Vibe 2.26.1, Claude Code
2.1.296) and names the release its protected paths (below) were audited
against (`audited_version`). glove refuses a manifest whose two differ, so a
new release goes in only with a re-audit. The base image tag is the `image`
version plus a hash of what it is built from (its `image/` context, glove-pty,
the entrypoint, the release), so a changed context is rebuilt, and the
derived images on it follow. Each harness's dependency tree is pinned in its
context: Pi installs from a committed `package-lock.json` (`npm ci
--ignore-scripts`; Pi 1.x ships no shrinkwrap), Vibe from a committed uv
constraints file; Claude Code is one native binary. An optional `brief:`
names a markdown file in the harness dir that is added to the agent's context
file (Pi's and Vibe's say their settings are read-only and a lasting choice
goes in the session file).

An adapter may also render read-only **system config** (`system_files`): files
in a directory of its own under `/etc`, written to `.glove/harness/` and bound
read-only like the ring-1 policies. Every enforcer with a tool wrapper also
renders it one argument per line (`tool-wrapper.argv`) beside
`tool-wrapper.json`, for glue that has no JSON parser. Both directories are
updated in place on a re-plan (a changed file replaced atomically, stale ones
removed), since a running session binds them.

**The harness home is read-only.** Ring 0 binds the session home
(`/home/agent`) read-only and re-binds only the harness's config home
(`config_home` in `harness.yml`: Pi's `.pi/agent/`, Vibe's `.vibe/`, Claude
Code's `.claude/`, the one place each was measured to write) read-write.
Anything else in the home, listed or not, fails with `EROFS` (why, and
nono's state on tmpfs: `docs/SECURITY.md`, "The harness home").

**What a harness loads is not the agent's to write.** The agent's file tools
run inside the harness process, which can write `/work` and its config home, so
ring 0 binds read-only what the harness would load from either. Each harness
lists them in one `protect:` list in its `harness.yml` (a trailing `/` marks a
directory, and the directories above one are pinned so they can't be renamed
aside):

```yaml
protect:
  - .claude/settings.json                     # the working dir: the repo's copy, read-only
                                              # (an empty placeholder when missing)
  - {path: .vibe/, source: empty}             # the working dir: always the empty placeholder
  - ~/.claude/settings.json                   # the home: its own copy (glove renders it)
  - {path: .vibe/skills/, opt_in: project_skills}  # the repo's copy, if that harness_config key is true
```

- **The working dir.** Claude Code's `.claude/settings*.json`, as the repo
  holds them. Vibe's `.vibe/` and `.agents/` are always the empty placeholder:
  a project hook runs before glove's and shadows one of the same name, so a
  repo's own Vibe config is not loaded under glove (put it in
  `harness_config`).
- **The home** (`~/`): its own copy (glove renders the files; a missing one
  is created empty). Pi: `settings.json`, `models.json`, `trust.json`,
  `auth.json` (rendered `{}`: `llm-auth` holds the key, and `/login` can't
  save), glove's brief `AGENTS.override.md` (an override there replaces
  `AGENTS.md`/`CLAUDE.md`, even an empty one), the empty `SYSTEM.md`,
  `APPEND_SYSTEM.md`, `mcp.json` and `keybindings.json` (Pi ignores an empty
  one), and `extensions/`, `skills/`, `prompts/`, `themes/`, `bin/`, `npm/`,
  `git/`. Vibe: `config.toml`, `hooks.toml`, `.env` and `tools/`, `plugins/`,
  `agents/`, `prompts/`, `skills/`. Both: `~/.agents` (outside the config
  home: read-only with the home). Sessions, logs and caches stay writable.
  glove re-renders the files at each start, so a choice the harness saves
  there (Pi's `/model` default, Vibe's `/theme`) never outlived a session; now
  the save fails silently (Pi even reports it as saved). A lasting choice goes
  in the session file (`harness_config`, or `llm`'s `model`). Claude Code:
  `settings.json`, `CLAUDE.md` and `agents/`, `commands/`, `skills/`,
  `plugins/`, `output-styles/`, `rules/`, `dev-mods/`; it still writes
  `.claude.json`, `projects/`, `sessions/` and its history, and `/model`'s
  "set as default" reports that it can't save.

Pi also skips the project's `.pi/` and `.agents/skills` (rendered
`defaultProjectTrust: never` and an empty trust store; a session may set
`harness_config.settings.defaultProjectTrust` to relax it). Its `AGENTS.md`
and Vibe's still load: they are prompts, like any file the agent reads.

Pi's session dir is pinned to its default (`PI_CODING_AGENT_SESSION_DIR`), so
a repo's `.pi/settings.json` can't move where sessions are written (see
[SECURITY.md](docs/SECURITY.md)).

**Vibe: the repo's skills, opt-in.** With

```yaml
harness_config:
  project_skills: true
```

the repo's `.vibe/skills/` and `.agents/skills/` show through the masked
`.vibe/` and `.agents/`, read-only; the rest of both stays empty. Off by
default: a documented widening (see [SECURITY.md](docs/SECURITY.md)).

The agent's file-write tools run in the harness process, so the hooks hold
them to the write roots (`/work`, rw mounts, `/tmp`, writable extension
channels): Pi's `write`/`edit` and
Vibe's `write_file`/`search_replace`, nested calls included, are refused into
the home, through a symlink or `..`, and (Pi) as `~` or `@path`. Pi's
enforcer then freezes a checked call, so a `tool_call` handler that runs after
it can't change it: the change throws and Pi refuses the call. Load only Pi
extensions you trust (see [SECURITY.md](docs/SECURITY.md)).

**The tool inventory fails closed.** Each harness's `harness.yml` lists its
tools (`tools:`) by what glove does with a call: `shell` runs under the tool
wrapper, `file_write` is held to the write roots, `allow` passes through, `ask`
is left to the harness's own prompt (Claude Code) and `deny` is refused. glove
renders the session's list as `/etc/glove/enforcer/tools.json` (read-only):
the harness's classes, the tools its extensions add (a Pi extension's
`pi: {tools: …}`; for Vibe, `mcp_<server>.<tool>` for each tool a glove MCP
server's allowlist names) and the session's own additions. Pi's enforcer
extension and Vibe's hook refuse any other tool, and every tool when the file
is missing, so a tool a new release adds or renames stays refused until glove
classifies it. **If you add your own Pi extension or a Vibe
`harness_config.mcp_servers` server, list its tools** (pass-through only):

```yaml
harness_config:
  tools:
    allow: [mcp_myserver.lookup]   # Vibe: a session MCP server's tool; Pi: an extension's tool name
```

A name glove wraps, holds or denies is refused at plan time. A Vibe MCP tool
is listed as `mcp_<server>.<tool>`, the name the agent calls from
`run_typescript`. The rest of Vibe's `harness_config.tools` (its own
`[tools.<name>]` tables) still goes to its `config.toml`. Your own
`harness_config.mcp_servers` render as written: one that keeps state per
session can use glove's bridge (`transport: stdio`, `command:
/opt/glove/bin/glove-mcp-bridge`, `args: [<url>]`).

Pi 1.x features, as glove renders them:

- **Built-in MCP: off** (`extensions: ["-builtin:mcp"]`). Pi starts stdio MCP
  servers from the harness process, outside ring 1. A session's own
  `harness_config.settings.extensions` are added after that entry, and any
  naming `builtin:mcp` is dropped: there is no opt-in until glove extensions
  contribute Pi MCP servers.
- **Codemode: off**, as Pi ships it. `harness_config: {settings: {defaultTools:
  ["+codemode"]}}` turns it on; its nested `tools.bash` and `tools.write` go
  through the enforcer like direct calls.
- **The fullscreen TUI** (Pi's default) works under glove's pty relay as is.

**git in `/work`.** Through Docker Desktop's file sharing, a `.git` the agent
just made can read as another uid, and git refuses it ("dubious ownership").
Every harness gets `GIT_CONFIG_PARAMETERS` naming the session's own mount roots
(`/work` and each add-dir) as `safe.directory`, exact paths only (the images'
git 2.39 has no `dir/*` patterns), so `git init` in `/work` works. A repo
nested deeper (a clone, or `git init` in `/work/<dir>`) needs an opt-in on
Docker Desktop (Podman's shares report the right owner): the `github`
extension adds `'*'`, or the session adds it with `git_config:`
(`git_config: { safe.directory: "*" }`; a key takes a value or a list). glove
alone sets git's config env vars: `env:` may not.

### Claude Code

```yaml
harness: claude-code
extensions:
  llm:
    provider: anthropic
    model: claude-sonnet-5-5
    auth: oauth                       # a subscription token from `claude setup-token`
    api_key: keychain:claude-code-me  # `glove keychain set claude-code-me`, then paste the token
    # auth: api-key + an API key works too (injected by llm-auth; Claude Code never holds it)
```

- **Image** `glove/claude-code:0.2.0`: the native Claude Code binary (pinned,
  auto-update off), nono, glove-pty and `glove-cc-prefix`; no Node.
- **Guard rails live outside the agent's reach**, in
  `/etc/claude-code/managed-settings.json` (read-only bind; managed settings win
  over every other scope, and an unparseable file stops Claude Code):
  - `CLAUDE_CODE_SHELL_PREFIX` → `glove-cc-prefix`: the Bash tool, `!`
    commands and hooks all run under the session's tool wrapper, and fail
    closed (exit 126) if it is missing. It is set only there, because the
    agent's own `settings.json` `env` would override a prefix in the process
    environment. A stdio MCP server runs as `glove-cc-prefix --mcp <name>`,
    from a read-only argv beside the settings, under the harness's sandbox
    (with network, as Pi and Vibe run theirs), not the tool wrapper;
  - only managed hooks, permission rules and MCP servers: a project's
    `.claude/settings.json` hooks and `.mcp.json` servers never run, nor do
    installed mods (plugin code in Claude Code's process); sideloaded plugins
    (`--plugin-dir`/`--plugin-url`) are refused, and `dev-mods/`, where Claude
    writes the mods it builds, is read-only;
  - Read denied on the config home (`//home/agent/.claude/**`), and Edit (every
    write tool) on the whole home and `/dev/shm`, which the harness process may
    write under `nono+srt` but a tool command may not: Write and Edit reach what
    a shell command reaches;
  - the project's `.claude/settings.json` and `settings.local.json` are bound
    read-only (ring 0, `protect:` in `harness.yml`; an empty placeholder
    when missing, and `.claude` pinned so it can't be moved aside): Claude Code
    applies their `env` and commands to processes it starts itself, outside
    the tool wrapper, so the agent must not write them;
  - the tools its inventory (`harnesses/claude-code/harness.yml`) classes
    `shell`, `file_write` or `allow` are pre-approved; the `ask` ones
    (`Workflow`, `Skill`, `Cron*`, …) and any a new release adds prompt, as
    Claude Code ships, unless `harness_config.tools.allow` pre-approves them;
    `EnterWorktree`/`ExitWorktree` are denied (they run git from the harness
    process, outside ring 1);
    `WebFetch` is allowed with `webfetch` (through the egress proxy:
    `HTTPS_PROXY` in the managed env, every session forwarder in `NO_PROXY`; see
    [SECURITY.md](docs/SECURITY.md) for what that widens) and denied without it;
    `defaultMode` is pinned to `default`
    (`harness_config.permissions.defaultMode` may pick `acceptEdits`, `plan` or
    `dontAsk`);
  - extensions' MCP servers are the only ones (`managed-mcp.json`): a server's
    `tools` allowlist becomes allow rules, and every other tool it is known to
    have (`all_tools`) a deny rule, so Claude Code never offers it (Playwright's
    `browser_run_code_unsafe` and `browser_evaluate` included);
  - non-essential traffic, telemetry, error reporting and auto-update off.
- **Key:** neither an API key nor a subscription token enters the harness:
  `llm-auth` injects it. With an API key `ANTHROPIC_API_KEY` holds the
  placeholder (pre-approved in `.claude.json`, so Claude Code doesn't ask about
  it). With a token `CLAUDE_CODE_OAUTH_TOKEN` does, and Claude Code keeps its
  default host, which `llm-auth` serves with a per-session CA
  ([extensions/llm/README.md](extensions/llm/README.md), residuals in
  [docs/SECURITY.md](docs/SECURITY.md)). The `anthropic` provider allows
  `auth: oauth` for `claude-code` only.
- **Home:** `settings.json` (model, no co-author trailer, `harness_config.settings`),
  `.claude.json` onboarding and `/work` trust merged into whatever Claude Code
  keeps there, `CLAUDE.md` (environment + brief). Contributed skills are linked
  from `/opt/glove/cc/.claude/skills` (baked) and loaded with `--add-dir`, so
  the agent can read a skill's files by the path Claude Code shows it.
  Transcripts: `projects/<cwd>/<uuid>.jsonl`, exported by `observe`.
- `harness_config` takes `settings` (user-scope settings), `permissions`
  (`defaultMode`, extra `allow`/`deny` rules) and `tools.allow`.
- `anthropic-compatible` runs Claude Code against any server that speaks the
  Anthropic Messages API (llama.cpp, vLLM, LiteLLM, a gateway).

## Extensions

An extension is a directory under `extensions/` with an `extension.yml`
manifest (`api: 2`): its settings schema, the endpoints (forwarders) the
harness may reach, image layers, harness contributions (MCP servers, skills, a
harness's own code), a brief for the agent, and optionally hardened sidecars.
Core validates all of it. To write one, see
[docs/extensions.md](docs/extensions.md) (the manifest keys, hooks, `glove.api`
and an extension's CLI).

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
  than its own session state, its outputs and inputs (below), and all of
  `work/` only with the `work` privilege (`github`'s sidecar, which pushes the
  agent's checkout); never a path inside `work/`. The services a manifest's
  `trust:` names get the session's `corporate_ca` from core, bound
  read-only at `/etc/glove/corporate-ca.pem` and never SELinux-relabelled, with
  `GLOVE_CORPORATE_CA` naming it; the image builds its own bundle from it. A
  read-only sidecar cannot take an environment-sourced compose secret (Docker
  refuses), so it gets one as `llm-auth` gets the LLM key: a `launch_env` hook
  fills an `environment:` key declared without a value, at `compose up`.
- **Channels** (`channels: {name: {services: [...]}}`, in-tree or trusted only)
  are a directory shared by the harness and some of the extension's sidecars: a
  session tmpfs volume at `/run/glove/<name>`, which every enforcer lets the
  harness and its commands write (and grants no network for). A relay's client
  leaves requests there as files and FIFOs; glove's seccomp below srt forbids
  Unix sockets, so there is no socket.
- **Outputs and inputs** (`outputs: {name: {services: [...]}}`, `inputs:` the
  same; in-tree or trusted only) are directories of the session,
  `<session>/<name>/`, beside `work/`. An output is written by the listed
  sidecars (at `/run/glove-output/<name>`) and read-only to the harness at
  `/work/<name>`; an input is written by the harness at `/work/<name>` and
  read-only in the sidecars at that same path. Not a subdirectory of `work/`,
  which the agent could swap for a link the sidecar's bind would follow at its
  next restart. `glove up` points out an old `work/<name>/` that still holds
  files the mount now hides.
- **The harness** only ever gets forwarders on its internal network.
- **Remote addresses** (`target: {address: host:port}`) are dialled only by the
  inference provider (`via: llm`), the egress provider (`via: wan`), or, for a
  trusted extension's sidecar, a LAN host the user named (`via: lan`, never a
  harness endpoint; core's routable `lan` network carries only those
  forwarders). `lan` is a direct route that bypasses the egress provider, so a
  `via: lan` address must be a private IPv4 address or a LAN name (one label,
  or under `.lan`/`.local`/`.home.arpa`/`.internal`); a public host is refused.
  A name is checked again where it is dialled: the forwarder resolves it once
  at start and dials only a private IPv4 answer (under `observe`, the gate
  checks each connection).
- **Harness mounts** from an extension (`mounts: {models: {setting: models_dir}}`)
  are read-only binds at `/mnt/<ext>-<name>` of a directory the user named in a
  `path` setting (such a setting may not have a default), checked like the
  session's own `mounts:` (never `.glove/`, `local/`, the session file, glove's
  home or another session's state).
- **Harness contributions** are harness-neutral where they can be, under
  `harness:` — `env`, `image` (`"*"` or per harness), `brief`, and:
  - `env: {K: value}` or `{K: {value: …, when: …, shell: false}}`: a value is set
    as rendered, even when empty; `when:` leaves the variable unset unless it
    matches; `shell: false` keeps it from shell commands (the tool wrapper
    unsets it; any enforcer but `none`), for a variable only the harness
    process uses. A
    `when:` (here, on endpoints, services, verify checks and list items) matches
    setting names, `harness`, `renders` (the contributions the harness renders,
    e.g. `renders: mcp` rather than a list of harnesses), dotted
    `slot.<slot>.<key>` (a `*` part matches any key, e.g.
    `settings.plugins.*.relay`, and gives what it found below), a list of
    allowed values, or `{set: true|false}` (whether the value is set at all);
  - `mcp: [{name, transport: stdio|http, …, tools: [...], all_tools: [...]}]`:
    an MCP server, rendered by harnesses that speak MCP. An item takes only
    the fields every harness renders alike: `name` (letters, digits, `_`, `-`;
    one per session), `transport` (`stdio`, the default, or `http`;
    `streamable-http` means `http`), `url` (http) or `command`, `args` and
    `env` (stdio), and `tools`/`all_tools` (a list or comma-separated). Anything
    else (`auth`, `headers`, one harness's timeouts) is refused. Vibe:
    `config.toml`, with `tools` as an allowlist that also enters the tool
    inventory as `mcp_<server>.<tool>` (so its server name is `[a-z0-9_]`);
    an `http` server is rendered as the image's stdio bridge
    `glove-mcp-bridge <url>`, since Vibe opens a new MCP session for every
    HTTP call and a server like Playwright keeps its pages per session.
    Claude Code: `managed-mcp.json`, `tools` as allow rules and the rest of
    `all_tools` as deny rules;
  - `skills: [skills/x]`: a `SKILL.md` directory baked into the image, or one
    from a mount (`{mount: m, path: skills/y}`, skipped when that mount is off),
    for every harness (Pi: `settings.json`; Claude Code: links under
    `/opt/glove/cc/.claude/skills`, `--add-dir`; Vibe: links under
    `/opt/glove/vibe/skills`, its `skill_paths`);
  - `<harness>: {...}`: a section only that harness's adapter reads, e.g.
    `pi: {extensions: [pi-extension], tools: [web_search]}` (glove renders no
    MCP for Pi: its built-in MCP is off, so it loads its own code with `pi -e`).
    `tools` (a list or comma-separated) names the tools that code registers;
    they join the tool inventory, and Pi refuses any it doesn't name.

  Any other key is an error. A `contribute` hook returns manifest keys
  computed at plan time (glove/manifest.py `KEYS` says which): under
  `harness:`, `image` layers, `env`, `skills` (container paths in the image)
  and `mcp` items, taken as given; and, for services its fragment renders from
  settings (`vars`, below), `channels`, `privileges`, `trust`, `exports` and
  `endpoints` entries, checked like the manifest's (lists add to the
  manifest's; a name both set is refused, unless the manifest's entry is
  `when:`-excluded), plus `verify` checks, `secret_refs` (label → `keychain:`/`env:` reference: the
  secrets nested deeper than a `secret` setting, which `glove check` verifies
  exist like the others) and `egress_hosts` (the names its sidecars reach, `*.x`
  for subdomains: `glove check` warns when an egress that filters by name, such
  as `corporate`, doesn't admit one). Only its layers may `copy_host` (host paths it checked; the `skills`
  extension's plugins): core renders those last, after the `stage: late` layers (the toolchains), so an
  edit to a checkout rebuilds nothing else, and refuses a source an agent can
  write (a read-write mount, `/work` included, or another session's `work/`)
  or glove's state.
- **Fragments** (`compose/services.yml.j2`, Jinja) see a restricted context,
  including `settings`, `session` (`id`, `subnet`, `secrets_dir`),
  `endpoint.<name>` (every endpoint's `host`/`port`/`url`),
  `own_endpoints.<name>` (the extension's own, `{host, port}`, e.g. for a
  sidecar dialling its forwarders), `state`, `mount`, `work`
  (`{{ work.host }}` the host dir, `{{ work.target }}` where the `work`
  privilege binds it), `images`, `slot`, `channel.<name>.path`,
  `output.<name>.path`/`input.<name>.path` (where a sidecar sees it),
  `exports` and `vars` (what the extension's `contribute` hook computed for
  it, e.g. one relay sidecar per plugin).
- **Hooks** (`hooks: hooks.py`) are host Python that core calls at fixed
  points: `contribute` (plan time), `materialize`, `forwarder` (the `forwarder`
  slot's provider), `launch_env`, `resolve`, `diagnose` and `doctor(ctx, probe)`.
  Each is marked `@hook` (`from glove.api import hook`; an unknown name fails at
  import, an unmarked one is refused) and gets a read-only `HookContext`
  (`ctx.settings`, `ctx.slot`, `ctx.state_dir`, …); what it returns is checked.
  The session and work directories are in it only when the manifest gives a
  reason (a `path` setting, `mounts`, `outputs`/`inputs`, a `work` privilege, or
  `host_files: true`) and the extension is trusted. That is hygiene, not a
  sandbox: a hook runs with your rights. An extension imports only `glove.api`
  from core (`tests/test_api_surface.py` lists it), loading as the package
  `glove_ext.<name>`, so it imports its own files relatively.
- **Out-of-tree** extensions load from `extension_paths:` in
  `~/.glove/config.yml`, are labelled *out-of-tree*, and cannot take privilege
  exceptions (or reach host ports) unless listed in `trusted_extensions:`.

`llm` is the inference engine, picked like a gluetun VPN provider: `provider:`
names a catalog entry (`extensions/llm/providers/*.yml`). `location:` routes it:
`host` → a forwarder to this Mac; `lan` → a forwarder that dials exactly the
configured `host:port`; `internet` → a forwarder to the provider's HTTPS host,
aliased so TLS runs end to end. With an API key the harness's forwarder leads
to the `llm-auth` sidecar instead, which holds the key
([extensions/llm/README.md](extensions/llm/README.md)). The harness never gets
LAN or internet reach itself. `model: auto` and `capabilities: auto` are resolved at launch from a
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
`container-healthy`, `tcp-open`, `http-ok`, `http-refused`,
`exit-confirmed` and `exec-ok`. `exit-confirmed` requires the egress's own software to report one
valid IP for its exit (vpn: the server it tunnels to; tor: the Tor Project's check, `IsTor: true`);
with the operator's `host_check_url` (no default), that service, asked from the host and through
the egress, must also see two different IPs;
`http-refused` requires the proxy to refuse a URL (corporate: the general
internet); `exec-ok` runs a command inside a sidecar and requires exit 0 (its
output withheld; `skills` checks a relay's credentials this way). The network
checks run from throwaway hardened containers on
the session's networks. A failing check shows the sidecar's last log lines (key
and password lines withheld) and stops the session's sidecars, unless it is a
`warn: true` check: then it is a warning and the session starts. VPN secrets are
Keychain references handed to gluetun as compose secrets. An optional
**register hook** in the session's `local/` can mint a fresh WireGuard key at
every `glove up` (see [extensions/vpn/README.md](extensions/vpn/README.md)).

**Privacy: no lookup service of glove's own.** glove adds no IP-lookup service: what the
session's exit is comes from the egress's own software.
- `vpn` records the VPN server's endpoint as its exit (read from gluetun's kill-switch rules; no
  lookup). That is the tunnel's entry address: a provider may send traffic out from another one.
  With no `host_check_url`, verify does not compare the exit with the host's IP. Its `publicip_api` setting (no default) turns gluetun's own lookup on, through the
  tunnel, with a service the operator names (gluetun's `PUBLICIP_API`).
- `tor` uses the Tor Project's check (`check.torproject.org`), through Tor: at verify, and with
  observe (its `exit_identity: auto` default) every 5 minutes from the proxy gate. Tor isolates circuits
  per client, so the exit observe records for tor is its gate's own, not necessarily the agent's.
- `direct` checks the proxy with an `http-ok` to `https://on.quad9.net` (`check_url`).
- The host's own IP is never looked up unless the operator sets `host_check_url`.
- vpn's DNS upstream and gluetun's health check use Quad9 by default (`dns_upstream`,
  `health_targets`; both overridable).

`search` runs SearXNG and valkey in the session, with every engine request
going through the egress proxy. `webfetch` reads one page as text through the
egress, refusing this machine, the LAN and metadata addresses (also on every
redirect). Pi gets its own `web_search`/`web_fetch` extensions (`webfetch`
through a `proxy` forwarder). Claude Code keeps its own `WebFetch`, pointed at
the same `proxy` forwarder; there the egress layer (the proxy's filter, the
tunnel's policy, or with `observe` the gate's SSRF guard) refuses this machine
and the LAN. Harnesses that speak MCP get `web_search` from a small hardened
sidecar served over HTTP (`search-mcp`), so the harness never reaches SearXNG
itself. Vibe gets `fetch_url` from a second one (`webfetch-mcp`), which
reaches the proxy only through its own hop (`webfetch-egress`; with `observe`,
a gate labelling its flows `client: webfetch`). Both need an egress provider.
`web_fetch`/`fetch_url` return text only: a PDF, an archive or an image is
described (`[binary: application/pdf, 812345 bytes] <url>`), never returned. An
`http://` URL goes to the proxy as a plain request, as a browser sends it
(only `https://` is tunnelled). With `webfetch: {downloads: work}` every
harness also gets `web_download`/`web_download_status`: the `fetcher` sidecar
saves files of any size to `<session>/downloads/` (read-only to the agent at
`/work/downloads/`) through the same egress and guard, as asynchronous jobs that
resume, with a `min_free` reserve on the host disk
([extensions/webfetch/README.md](extensions/webfetch/README.md)). On macOS
`glove down` (or `glove downloads mark` mid-session) stamps the quarantine
attribute on new files there and in the browser's `browser-output/`, so
Gatekeeper vets one opened from Finder.
The `pi-search` template puts it together: `glove new pi-search <dir>`.

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
    exit_identity: auto       # auto: ask the egress (vpn's endpoint, tor's check) | none | an https:// URL
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
net/exit.ndjson     apparent-origin changes (exit_identity; absent until the exit is known)
net/status.json     gate heartbeat, upstream health, dropped-record counters, and —
                    only with filter — the rules load result (the enforced file's SHA-256)
```

Each service in `session.json` lists `next`: the egress forwarders (`harness:
false`) that the sidecars behind it dial out through, so a monitor can join a
harness hop to the egress flows it causes: `search` and `search-mcp` →
`searxng-egress`, `webfetch-mcp` → `webfetch-egress`, `webdownload-mcp` →
`webdownload-egress`, `browser` → `browser-egress`, `llm` → `llm-upstream` when
glove injects the key. A skipped egress gate is still listed (`observed:
false`). It is `[]` for a hop whose target is not a sidecar (`proxy`,
`github-egress`, `ssh-<name>`), for a second hop (`<name>-out`) and for the
egress forwarders themselves (their target is the egress proxy). observe infers
it from the networks a hop's target shares with the egress forwarders; an
endpoint whose sidecar has several names them in `observe: {feeds: [...]}`
(webfetch's two fetcher hops).

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
`tests/fixtures/netobs-v3/` (one `~/.glove` tree per grant state and per hop
shape: injected LLM key (`llm-auth`, `llm-auth-oauth`), `github`, `ssh` with a
`builtin:lan-only` refusal, Vibe `downloads`; generated by
`extensions/observe/tests/fixtures/generate.py`; the Vibe transcript is in
Vibe's layout before 2.26, which now writes a journal under `unified/`). On Podman, sidecar binds are
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
(file, page, char/line) back to the original. Every harness gets the
`rag-parse` and `rag-query` skills. Embeddings run in-process (fastembed) from `models_dir`, a
read-only mount filled once by `glove rag fetch-model`; `obsidian_dir` (a
claude-obsidian checkout, read-only) adds its vault-synthesis skills. No egress
provider is needed. Template: `glove new pi-rag <dir>`; details in
[extensions/rag/README.md](extensions/rag/README.md).

### Plugins and skills: `skills`

**`skills`** loads Claude Code plugins, and plain directories of skills, into
every harness. Clone a plugin into the session's `skills/` directory (never
mounted, like `local/`) and name it:

```yaml
extensions:
  skills:
    plugins:
      connectors:                                   # your name for it ([a-z0-9-])
        path: skills/connectors-repo/plugins/connectors  # .claude-plugin/plugin.json, or a dir of <skill>/SKILL.md
        skills: [confluence, slack]                 # default: all of them
        env: { WIKI_SPACE: team }                   # plain values only: a secret is refused
      notes:
        path: skills/notes-repo/notes
        mcp: true                                   # its .mcp.json servers (Claude Code, Vibe; Pi has no MCP)
        tools: { notes: [search, fetch] }           # each server's allowed tools (required)
```

The plugin is baked into the harness image at `/opt/glove/plugins/<name>/`
(content-addressed, in the image's last extension layer: an edit rebuilds
only that layer on the next `glove up`; nothing is bind-mounted). Only the
selected skills are staged, with the plugin's other files. In the baked copy,
`${CLAUDE_PLUGIN_ROOT}` and `${CLAUDE_PLUGIN_DATA}` are replaced in the
Markdown that names them (the data dir is `/work/.glove-plugin-data/<name>`,
created by glove), and `bin/` is linked into `/usr/local/bin` (a name the image already
has fails the build rather than shadow it). Skills load through the neutral
`skills` contribution, so Claude Code takes them with `--add-dir` and its
plugin refusal stays. PEP 723 scripts (`uv run --script` shebangs) run offline
on a baked Python (`python:`, default 3.12): each set of dependencies is
installed at build time into its own read-only environment (wheels only; an
sdist-only dependency fails the build) and the shebang points at it, because
the harness's `/tmp` is noexec and a compiled extension could not load from a
uv cache there. An explicit `uv run --script` still works for pure-Python
dependencies (the env points uv at the baked wheelhouse). Scripts run under the
tool sandbox like any command: no network. Refused at plan time: a plugin an
agent can write (`/work`, a read-write mount, another session's `work/`: it
could edit what the next session bakes) or in glove's state, a symlink leaving the plugin, a file that looks like a credential
(`.env`, `.netrc`, `.npmrc`, `.pypirc`, `*.p12`, SSH keys, a PEM private key),
and a secret-shaped name or a `keychain:`/`env:` reference in `env`. A plugin's
stdio MCP server runs under the tool wrapper (`glove-confine`: the per-command
sandbox, no network), never with the harness's own network, which reaches the
session's forwarders. Plugin hooks, commands and agents are not loaded.

Scripts that need a service and its credential run in a **relay** instead: a
sidecar of the plugin's own (`skill-<name>`), which holds the secrets and the
only route to the service's hosts. In the baked copy each such script is a shim
to it, at the path the skill names, so the skill is unchanged:

```yaml
      connectors:
        path: skills/connectors-repo/plugins/connectors
        relay:
          commands:
            scripts/wiki_query.py:
              hosts: [wiki.corp.example]                # its egress fence: port 443 to these only
              allow: [search, fetch, children]          # its first non-flag argument; `*`: any
              out_flags: [-o, --output]                 # a value must be a path under /work
              env: { WIKI_PAT: keychain:corp-wiki-pat } # or {secret: keychain:…, refresh: local/mint.sh}
            scripts/chat.py:
              hosts: [chat.example.com, "*.chat.example.com"]
              allow: [read, history, search]
              files:                                    # rendered into the script's own home, 0600
                ~/.config/chat/auth.json:
                  template: local/chat-auth.json.j2     # {{ secrets.token }}
                  secrets: { token: keychain:corp-chat-token }
          check: ["scripts/wiki_query.py search glove -n 1"]   # at `glove up` (a warning) and in `glove skills status`
```

Each relayed command gets its own environment, home and fence; its secrets are
resolved at `glove up`, in memory (a `files:` template too: written only in the
sidecar's tmpfs), and never enter the harness. A subcommand not listed is
refused, so a script's minting or posting commands run only when you list them.
Relayed scripts run on the relay's Python (standard library only) with no
stdin, and any argument that names a path must be under `/work`. When a token
expires: `glove skills status` runs the checks, `glove skills refresh <plugin>
[<secret>…]` stores new values (all the relay's Keychain secrets, or only the
ones named, by service or by the env var using it; each printed by its
`refresh:` hook, run on this machine with the Keychain service name, captured
by `glove playwright login`, or typed at a prompt where Enter keeps the stored
value) and `glove skills reload <plugin>` recreates only that relay's
sidecar, with the harness and the agent's conversation left running. Details in
[extensions/skills/README.md](extensions/skills/README.md).

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
other `playwright_*` tool (`browser_run_code_unsafe` included), and Claude Code
gets allow rules for them and a managed deny rule for every other tool the
pinned MCP has. A private CA
for the sidecar is `playwright: {ca: <pem>}`. It is set separately from
`corporate_ca`, so set both when the browser is used. The sidecar's Node trusts it
through `NODE_EXTRA_CA_CERTS` and Chromium through an NSS import. With
`downloads: work` what the browser saves lands in `<session>/browser-output/`
(read-only at `/work/browser-output/`); with `uploads: work` it uploads from
`/work/browser-uploads/` (read-only in the sidecar). For single sign-on,
`glove playwright login` opens a dedicated Chrome on your machine (a fresh
profile, CDP over a pipe, no port): you sign in, with your Keychain identity
if the IdP asks for one, and glove stores only the cookies and localStorage of
the hosts in `login.domains` (`storage_state`) and the named `login.capture`
values (for plugin relays), each in the Keychain, never printed or on disk. The
sidecar starts from the stored session (`profile: ephemeral`), and the tools
that would hand it to the model are refused. Template:
`glove new browse-watch <dir>`; details in
[extensions/playwright/README.md](extensions/playwright/README.md).

### Relays: `github`, `ssh` (and the `relay` library)

`gh`, and `git push`/`fetch`/`pull`/`clone`/`ls-remote`, work from the agent's
shell, with every other shell command still offline. Shims in the harness image
relay each call over a channel to a sidecar holding the tokens, which runs the
real command under a policy. The hosts it serves are github.com (`token:
keychain:<service>`) and each GitHub Enterprise host named in `hosts: [{host,
token}]`, a token each (`token`, `hosts` or both):

- **gh:** an allowlist of subcommands; `auth`/`secret`/`extension`/… never
  (`gh auth token` is refused); `gh api` GET only; served hosts only. With
  Enterprise hosts only, the first is gh's default host.
- **git:** the network verbs in `git:` (default `push`, `fetch`, `clone`,
  `ls-remote`; `[fetch, clone, ls-remote]` for a read-only session) to
  `https://<served host>/<owner>/<repo>` remotes only, with the repo's own config
  defanged (no hooks, helpers, fsmonitor, other protocols); one credential helper
  per host, each with that host's token.
- **Files:** file arguments are opened inside `/work` only.
- **Network:** traffic reaches the served hosts only (an Enterprise host and its
  subdomains), through an in-process fence and then the egress (with `observe`,
  a gate: `client: github`). Behind the `corporate` egress, `glove check` warns
  about a served host `allow_domains` doesn't admit; one on a private address
  needs `allow_cidrs` (or `from_interface`) to cover it too.

The sidecar binds `/work` read-write (the `work` privilege) so pushes and PRs
work on the agent's checkout. The token never enters the harness. Use a
fine-grained token. Details:
[extensions/github/README.md](extensions/github/README.md),
[extensions/relay/README.md](extensions/relay/README.md),
[docs/SECURITY.md](docs/SECURITY.md#relays-gh-and-git-from-shell-commands-relay-github).

`ssh <host> <command>` works the same way, to the hosts the session names
(`ssh: {key: keychain:<service>, hosts: [{name, to, user}], known_hosts:
local/known_hosts}`):
- **The key** sits in an `ssh-agent` in the sidecar.
- **Routes:** each host gets one forwarder on core's `lan` network, which is
  the sidecar's only route; with `observe`, a gate labels it `client: ssh`,
  `scope: lan`.
- **Host keys** are checked strictly against the session's `known_hosts`.
- **Refused:** port forwarding, jump hosts, `ProxyCommand`, identities and a TTY.

Details: [extensions/ssh/README.md](extensions/ssh/README.md).

### Credentials: store, check, renew

Every credential a session uses is a `keychain:<service>` reference in the
session file (or `env:<VAR>`), resolved in memory at `glove up` and handed to
the one sidecar that uses it. None enters the harness or a file on disk.

| Credential | Held by | Stored with | Checked by | Renewed |
|---|---|---|---|---|
| the model's key (`llm.api_key`) | `llm-auth` | `glove keychain set` | `glove check` (the item exists), the model probe at `glove up` | `glove down`, then `glove up --resume` |
| a GitHub or Enterprise token (`github`) | the `github` relay | `glove keychain set` | `glove check`; `gh api user` from the agent's shell | `glove down`, then `glove up --resume` |
| a plugin script's secret (`skills…relay`) | that plugin's relay | `glove keychain set`, `glove skills refresh`, or a `login.capture` | `glove skills status` (the relay's `check`) | `glove skills refresh <plugin>`, or `glove skills reload <plugin>` after a new capture; the agent keeps running |
| a signed-in browser session (`playwright.storage_state`) | the browser sidecar | `glove playwright login` | `glove playwright status` (the earliest cookie expiry) | `glove playwright login` (it reloads the sidecar); the agent keeps running |

For a corporate session ([templates/corporate](templates/corporate/)) the
order is: the `corporate` allowlist first (every host a relay or the browser
reaches, plus its private range in `allow_cidrs`); then the tokens (`glove
keychain set <service>`, pasted or `--stdin`); then `glove playwright login`
when a plugin relay uses a captured browser value; then `glove check` (it
reports each missing Keychain item, and each host a relay, GitHub or the
signed-in browser reaches that the allowlist doesn't admit by name; whether a
private address is inside `allow_cidrs` is yours to check) and `glove up`. When a short-lived value expires mid-session, the agent is told to
ask you for the refresh command, never to mint or store a credential itself.

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
  Every secret-shaped env name (`*KEY*`, `*TOKEN*`, …, in any case, whoever
  set it; the list: [SECURITY.md](docs/SECURITY.md)) is unset before a command
  runs (`glove-pty notty -u <glob>`), and nono or srt strip them again.
- **Ring 2 - Harness integration**: a Pi extension / Vibe `pre_tool` hook routes
  every `bash`/`!` command through ring 1 (nested calls too), holds the
  file-write tools to the same write roots as ring 1, and refuses every tool not
  in the session's tool inventory (fail closed; Claude Code prompts for one
  instead); a generated context file tells the agent the rules.

See **[docs/SECURITY.md](docs/SECURITY.md)** for the full threat model and the
Docker Desktop macOS blast-radius explanation.

### Enforcer: `nono+srt` (the default on Docker)

```yaml
enforcer: nono+srt    # what a session gets on Docker when it names no enforcer; `nono` on Podman
```

```
glove-pty relay -- glove-srt srt-harness.json -- glove-pty ctty -- pi …
  every shell command: glove-pty notty -u '*KEY*' … -- nono wrap --profile tool.json -- bash -c <cmd>
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
| Runtime | podman | hardened + doctor probes; v3 session dirs verified live on Podman Desktop (macOS, podman 6.1.2 rootless, applehv, Landlock ABI 9): `test_session_dir`, `test_pi_nono`, `test_vibe_nono`, `test_tool_confine`, `test_llm_inject`, `test_ring0_protect`, `test_toolchains` (Chromium under plain nono), `test_config_protect` (Pi, Vibe), `test_vibe_skills`, `test_teardown`; srt and nono+srt are refused on podman. Runs alongside Docker Desktop (each runtime has its own VM, image store and networks) |
| Runtime | apple-container / gondolin / utm | stub (registered, `NotImplementedError`) |
| Enforcer | nono (Landlock) - default on podman | nono 0.78.0; Pi and Vibe verified (`test_pi_nono`, `test_vibe_nono`, `test_config_protect`, `test_tool_confine`, `test_vibe_skills`) |
| Enforcer | nono+srt - default on docker | srt wraps the harness (deny-inside-allow writes, `.env` hidden, no namespaces/mounts below it), nono every command; verified live on Docker with Pi, Vibe and Claude Code (`test_nono_srt.sh`, `test_config_protect.sh`) and under every extension suite (egress, observe, playwright, corporate); refused on podman |
| Enforcer | srt (bubblewrap) - opt-in | srt 0.0.77 with glove's `apply-seccomp`; Pi verified (`test_pi_srt.sh`: env/`/proc` key leaks, no user namespaces); `test_config_protect.sh` with Pi, Vibe and Claude Code; tool commands only |
| Enforcer | none (ring 0 only) | debug |
| Inference | `llm` extension: openai-compatible (default; vLLM, NInfer, …), anthropic-compatible, llama.cpp, ollama, lmstudio, openai, anthropic, mistral, openrouter | `host` verified live (stub llama-server, stub Anthropic server); `lan` verified live (`openai-compatible` → NInfer over the user's VPN, `model: auto`, key by Keychain reference, Pi answered); `anthropic` verified live with Claude Code and a subscription token (`auth: oauth`, paginated model list, with and without `observe`); other cloud providers **untested**. Key injection (`llm-auth`) verified live against the stubs: Pi, Vibe and Claude Code on Docker, Pi on Podman (`test_llm_inject.sh`); a subscription token in `llm-auth` (TLS as `api.anthropic.com`, the session CA) against a stand-in for the provider on Docker and Podman (`test_llm_inject.sh claude-code-oauth`); through a real LAN server, a cloud provider with an API key, or a real subscription (`test_cc_account.sh`): **untested** |
| Harness | `claude-code` | verified live on Docker under nono and nono+srt against a stub (`test_cc_nono.sh`: prefix fail-closed, managed settings read-only, prefix survives the agent's settings, config home denied to Read/Write, project hooks and `.mcp.json` inert, a glove stdio MCP server under the harness sandbox with network, project settings unplantable by the Write tool or a command, every tool it offers in its inventory, a `cd` not carried into the next Bash call, Write denied in the home and `/dev/shm`, transcripts; `test_nono_srt.sh claude-code`; `test_config_protect.sh claude-code`: the protected home read-only, the home outside `.claude/` read-only, `.claude.json` and sessions still written, `--continue` resumes) and against a real account (`test_cc_account.sh`, opt-in). With extensions (against the stub): `search` over its MCP sidecar and its own `WebFetch` through the egress proxy, private destinations refused there (`HARNESS=claude-code test_egress.sh direct`), `playwright` headless with observe (`test_playwright.sh claude-code`: allowlisted tools only, a denied tool never offered, the SSRF guard at the gate); `rag`/`ocr` skills with Claude Code: **untested**; Podman: **untested** |
| Egress | `vpn` (gluetun, WireGuard/OpenVPN, optional register hook) | verified live on Docker and Podman (WireGuard through a register hook, keys from the Keychain: tunnel healthy, `egress-up` (Quad9 through the tunnel), `exit-confirmed` (the endpoint from gluetun's kill switch; a gluetun restart removes and rewrites it), search and web_fetch through the tunnel; with `observe`: flows `route: vpn`, destinations resolved in-tunnel by gluetun's DNS, `exit_identity: auto` an `exit` record (`vpn-endpoint`) from the `exit` volume, read-only in the proxy gate; also under `nono+srt` on Docker); the opt-in `publicip_api` and `host_check_url`, OpenVPN and built-in gluetun providers **untested** |
| Egress | `tor` (tor + privoxy), `direct` (tinyproxy) | verified live on Docker and Podman: only the provider on `wan`, SearXNG and the harness network have no direct internet, Pi `web_search`/`web_fetch` through the egress; two sessions concurrently. `exit-confirmed` (tor: the Tor Project's `IsTor`), direct's `egress-up` (Quad9) and, with observe, tor's `exit` record (`exit_identity: auto`): verified live on Docker, on Podman **untested**. The `search-mcp`/`webfetch-mcp` sidecars (Vibe, Claude Code): verified live on Docker with `direct` (MCP only under the forwarder's Host, sidecars unreachable from the harness network, the fetcher without direct internet, the fetch guard incl. a redirect into loopback); behind tor/vpn and on Podman **untested** |
| Egress | `corporate` (a default-block netgate proxy + allowlist) | verified live on Docker and Podman with a public host standing in for a corporate one (allowed host reached, everything else refused with the gate's reason, host gateway/metadata/own network refused even inside an allowed CIDR, raw TCP endpoint); **through a real corporate VPN: untested** (the operator runs it) |
| Downloads | `webfetch` `downloads: work` (`web_download`) | verified live on Docker with Pi, Vibe and Claude Code over vpn (WireGuard through a register hook) and direct, with observe + filter, and Pi on Podman (`test_downloads.sh`): files only in `<session>/downloads/` (the fetcher's bind, also after a restart), read-only at `/work/downloads/` (no write, no planted link), the harness-only vars absent from a tool command; a PDF's sha256 equal in the tool, the host and the shell, `glove-ocr` on it; a 3.8 GB Debian DVD as a job (`.part` visible, the harness answering meanwhile, the fetcher at ~55 MiB, sha256 = SHA256SUMS); a `glove filter` block and the `min_free` reserve refusing; `glove downloads mark` and `glove down` stamping the quarantine attribute and keeping an existing one. Gatekeeper's prompt for a stamped file: **untested** |
| Observability | `observe` (read) + `filter` (write) | verified live on Docker and Podman (direct and tor): every forwarder a netgate, flows for the harness's tools and SearXNG's engines, in-tunnel resolution over Tor, transcripts exported, `glove filter block` enforced and confirmed by SHA-256, revocation; `netgate_control_perms.sh` and `test_netgate_shutdown.sh` on both |
| Documents | `ocr` (tesseract/ocrmypdf/poppler + `glove-ocr`), `rag` (kstore: Obsidian vault + FAISS, fastembed in-process) | verified live with Pi on Docker and Podman: `glove-ocr` on a PNG, a scanned PDF page and a text-layer PDF; `kstore sync` (scan and image OCR'd, index built from the read-only model mount, offline) and `kstore ask` citing the original scanned page, all as Pi `bash` tool calls in the nono tool sandbox; rag and claude-obsidian skills in Pi's prompt. **Vibe: untested** (kstore via uv; skills through `skill_paths`, as `skills`) |
| Plugins | `skills` (Claude Code plugins and skill dirs, baked) | verified live on Docker (nono+srt) and Podman (nono) with Pi, Claude Code and Vibe, against the stub with the fixture plugin (`test_skills.sh`): scripts by the paths the skill names (stdlib, a dependency, a compiled dependency, an explicit `uv run --script`), `bin/` on PATH, paths resolved in the baked skill, the unselected skill absent, the plugin read-only and its data dir writable, the skill loaded (Pi's prompt, Claude Code's Skill tool, Vibe's `skill` tool), the plugin's stdio MCP server under the tool wrapper (Claude Code, Vibe: it answers and can't reach the llm forwarder), no network. Real-world plugins (an MCP server with compiled dependencies): built and their commands run by hand in the image; in a session **untested**. Relays (`test_skills_relay.sh`, a public bearer echo behind `direct`): Pi, Claude Code and Vibe on Docker (nono+srt) and Podman (nono) — the token in no session file and never in the harness, an unlisted subcommand, a path outside `/work` and a host the relay doesn't name refused, an expired token seen by `glove skills status` and a `glove up` warning, `refresh` through a hook, then `reload` with the harness left running. Behind `corporate` (`CORPORATE=1`: a stand-in API over TLS from a throwaway `corporate_ca`): Pi, Claude Code and Vibe on Docker, Pi on Podman — the relay's sidecar trusts the CA, the stand-in sees only the right token, and `glove check` warns when the allowlist doesn't admit the relay's host. The real connector scripts: **untested** |
| Browser | `playwright` `headless` / `novnc` sidecars | verified live with Pi, Vibe and Claude Code (headless) on Docker (sandbox on) and Podman (`chromium_sandbox: "off"`: podman compose cannot apply the `chromium-userns` seccomp profile, and glove refuses rather than dropping it): no ports, no capabilities, only on an internal network with no DNS or route; browsing through the egress; flows `client: playwright`, `glove filter` and the SSRF guard enforced at the gate; the agent offered only the allowlisted tools; `glove playwright view` loopback-only with Host/Origin checks; view-only and clipboard-off enforced by the VNC server (an RFB click lands only with `allow_control` and the full password). Behind vpn/tor/corporate: **untested** (direct egress only). `downloads: work`/`uploads: work` verified live on Docker (`test_playwright.sh downloads`): with Pi, Vibe and Claude Code a `.7z` and a 2 GB ISO (above the 768 MB `/tmp`, staged on disk) land in `<session>/browser-output/`, read-only to the shell; with Pi and Claude Code `browser_file_upload` sends files from `/work/browser-uploads/` only (a link there still names a sidecar file: SECURITY.md). With Vibe, glove's stdio bridge keeps one MCP session per server, so a click after a navigate (and so an upload) works: verified live on Docker (`test_playwright.sh vibe` and `downloads`, also across two `run_typescript` calls); the bridge itself on Docker and Podman (`test_mcp_bridge.sh`); the Vibe browser case on Podman: **untested** |
| Relay | `github` (`relay` library: channel + relayd + fence) | verified live on Docker against the stub (`test_github.sh`): Claude Code under nono and nono+srt, Pi under nono+srt — channel present, token absent from the harness, every policy refusal, `gh`/`git ls-remote`/`clone`/`pull` through the sidecar against public GitHub, shell still offline; `OBSERVE=1` flows `client: github`. With a real token (Keychain): `gh api user`, `gh pr list`, `gh api` GET (with `OBSERVE=1`), and against a scratch repository a push of a throwaway branch, seen on GitHub and deleted again (nono+srt); local git on fresh checkouts. GitHub Enterprise hosts (`test_github_ghes.sh`): two stand-in hosts with a token each, behind `corporate`, over a private CA (`corporate_ca`), `git: [fetch, clone, ls-remote]` — Pi on Docker (nono+srt) and Podman (nono), Claude Code and Vibe on Docker; a real GHES: **untested**; Vibe, `srt`, behind tor/vpn: **untested** |
| Relay | `ssh` (`via: lan` forwarders) | verified live on Docker with Claude Code under nono and nono+srt and Pi under nono+srt against a real LAN host and a Keychain-held key (`test_ssh.sh`: key absent from the harness, `ssh <host> <command>` as the configured user with the exit code back, every refusal, no route from a shell, the sidecar only through its forwarder; `OBSERVE=1` flows `client: ssh`, `scope: lan`; `SSH_LAN_ONLY=1` a host whose `.lan` name resolves public, refused by its gate as `builtin:lan-only` with zero bytes, verified with Pi under nono); Vibe, `srt`, Podman, a key with a passphrase: **untested** |
| Browser | `playwright login` + `storage_state` (sign in on the host, the sidecar seeded) | verified live (`test_playwright_login.sh`): a headless host Chrome (CDP over a pipe) signs in to a stand-in site; only `login.domains`' cookies kept (a parent-domain HttpOnly SSO cookie included), a cookie and a localStorage token captured, each in the Keychain; the sidecar signed in only after `glove playwright reload`, through the `corporate` gate; a typed `javascript:` URL runs nothing in the signed-in page (Chromium policy); the state file 0600 on its tmpfs, out of the MCP's and Chromium's environment, `file:` refused; no value in a session file or in what the model saw — Pi, Claude Code and Vibe on Docker (nono+srt), Pi on Podman (nono, `chromium_sandbox: "off"`). A real IdP with a client certificate from the Keychain, a headed login: **untested** |
| Browser | `playwright` `mode: host` | implemented; MCP pinned (`playwright-core@1.63.0 mcp`); per-session Chrome profile and ports; refused behind vpn/tor, and with Vibe or Claude Code unless `i_accept_host_rce: true`; host-side start **untested** |

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
uv run ruff check glove harnesses extensions tests   # lint
uv run pytest -q                           # unit suite (includes the layering check)
uv run lint-imports                        # core (glove/) must not import extensions/
# integration (need Docker; build the images first):
bash tests/integration/test_pi_nono.sh    # nono / Pi  (19 checks)
bash tests/integration/test_vibe_nono.sh  # nono / Vibe (12 checks)
bash tests/integration/test_mcp_bridge.sh  # Vibe's stdio MCP bridge in the Vibe image vs a stand-in (13 checks)
bash tests/integration/test_pi_srt.sh     # srt  / Pi  (12 checks)
bash tests/integration/test_nono_srt.sh pi    # nono+srt in a real session (32 checks; also: vibe 32, claude-code 28)
bash tests/integration/test_ring0_protect.sh  # ring-0 ro binds over .git/hooks etc. (15 checks)
bash tests/integration/test_config_protect.sh vibe nono  # the harness's config vs the agent, the home
                                              # read-only outside the config home, --continue, secret
                                              # env, Pi's session dir (14 checks; also: pi 13,
                                              # claude-code 12; any enforcer)
bash tests/integration/test_vibe_skills.sh nono  # Vibe's project_skills off, then on: only skills/
                                              # shown, read-only, a project hook never runs (8 checks)
bash tests/integration/test_tool_confine.sh pi  # the hooks' tool names by effect: shell wrapped, file
                                              # writes held to the roots, Pi's MCP off, the tool
                                              # inventory fails closed, a checked call
                                              # can't be changed after the check, secret env
                                              # (any case, set by glove or not) gone (26; vibe 19)
bash tests/integration/test_teardown.sh pi nono   # one harness per session, git config, `glove down` (9 checks)
bash tests/integration/test_session_dir.sh    # session dir lifecycle vs a stub llm (12 checks)
bash tests/integration/test_cc_nono.sh        # Claude Code's guard rails vs a stub (29 checks per enforcer)
bash tests/integration/test_egress.sh tor     # egress + search + webfetch end to end (also: direct;
                                              # vpn with VPN_SETTINGS=… [VPN_LOCAL=<hook dir>]) (11 checks)
HARNESS=claude-code bash tests/integration/test_egress.sh direct  # search MCP + WebFetch via the proxy
                                              # (13 checks; also: vibe 16; OBSERVE=1 adds flows)
bash tests/integration/test_playwright.sh claude-code  # the browser sidecar with Claude Code (21 checks;
                                              # also: headless, novnc, control, vibe)
HARNESS=claude-code bash tests/integration/test_playwright.sh downloads  # browser downloads/uploads
                                              # (28 checks; pi 27, vibe 27;
                                              # BIG=1 adds a 2 GB download)
bash tests/integration/test_downloads.sh direct  # web_download end to end, observe + filter (20 checks
                                              # on macOS with OCR=1; also: vpn with VPN_SETTINGS=…,
                                              # HARNESS=vibe|claude-code, RT=podman; BIG=1 adds a
                                              # large ISO as a job, BIG=dvd a ~4 GB one)
bash tests/integration/test_playwright_login.sh  # `glove playwright login` + storage_state: a headless
                                              # host Chrome signs in to a stand-in site, the sidecar is
                                              # seeded through corporate (20 checks; also: claude-code,
                                              # vibe, RT=podman SANDBOX=off)
bash tests/integration/test_github.sh         # the github relay vs a stub, nono + nono+srt (27 checks each;
                                              # OBSERVE=1 adds flows: 29; GH_KEYCHAIN=… a real token, read-only
                                              # (31 with OBSERVE=1); GH_SCRATCH_REPO=owner/repo also a push (36))
bash tests/integration/test_github_ghes.sh    # GitHub Enterprise hosts vs a stand-in (two hosts, a token each,
                                              # corporate egress, a private CA, read-only git) (16 checks;
                                              # also: claude-code, vibe, RT=podman)
SSH_TEST_HOST=… SSH_TEST_USER=… SSH_KEYCHAIN=… bash tests/integration/test_ssh.sh  # the ssh relay vs a LAN
                                              # host you name, nono + nono+srt (22 checks each; OBSERVE=1: 24;
                                              # SSH_LAN_ONLY=1 also a `builtin:lan-only` refusal: 25)
bash tests/integration/test_observe.sh direct # observe + filter end to end (also: tor) (29 checks with direct)
bash tests/integration/test_llm_inject.sh pi  # the LLM key only in llm-auth (also: vibe, claude-code) (15 checks;
                                              # claude-code-oauth: a subscription token, 28)
bash tests/integration/test_subnet_race.sh    # another network takes the subnet at compose up (7 checks)
bash tests/integration/test_corporate.sh      # corporate egress, a public host as stand-in (11 checks)
bash tests/integration/test_netgate_shutdown.sh   # clean down / killed forwarder records (9 checks)
bash tests/integration/netgate_control_perms.sh   # who can read/write net/ and rules.json (6 checks)
bash tests/integration/test_toolchains.sh     # pinned node/python + deps + Chromium, offline (42 checks;
                                              # 40 with RT=podman: no srt session)
bash tests/integration/test_skills.sh pi      # a Claude Code plugin baked and used (11 checks; also:
                                              # claude-code 14, vibe 13: its stdio MCP server)
bash tests/integration/test_skills_relay.sh pi  # a plugin relay: token expiry, refresh, reload (14 checks;
                                              # a throwaway Keychain item, deleted; a public echo host;
                                              # CORPORATE=1: a stand-in behind corporate with a CA, 18)
# RT=podman runs every script above except test_pi_srt on Podman (test_nono_srt checks the refusal);
# KEEP=1 leaves a driver's session running
# (images are per runtime: `glove build pi --provider podman`)
uv run python tests/integration/tui_probe.py <session-dir> '/model\r'  # drive a harness TUI on a pty by hand
bash tests/integration/test_llm_host_stub.sh  # llm location: host vs a stub llama-server, Pi answers
bash tests/integration/test_llm_lan.sh HOST:PORT [KEYCHAIN_SERVICE]  # llm location: lan vs your server
```

The core in `glove/` is kept minimal (about 8.5k lines of Python); in-tree
extensions live in `extensions/`, templates in `templates/`. The import boundary is enforced by
[import-linter](https://import-linter.readthedocs.io/): `glove` must never import
`extensions`, the same way a kernel never depends on its modules.
