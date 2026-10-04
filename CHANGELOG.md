# Changelog

All notable changes to glove are documented here.

## [Unreleased]

### Added

- **Claude Code harness** (`harness: claude-code`, image
  `glove/claude-code:0.2.0`: the native binary, pinned, no Node). glove's
  guard rails are read-only managed settings at `/etc/claude-code`: a shell
  prefix (`glove-cc-prefix`) that runs every Bash tool, `!` and hook command
  under the ring-1 tool wrapper and fails closed, and each glove stdio MCP
  server (`--mcp <name>`, from a read-only argv) under the harness sandbox,
  with network; managed-only hooks, permission rules and MCP servers; the
  config home denied to Read/Edit; non-essential traffic off. The project's
  `.claude/settings.json` and `settings.local.json` are read-only to the agent
  (their `env` reaches processes Claude Code starts outside ring 1). The home
  gets `settings.json`, a merged `.claude.json` (onboarding, `/work` trust) and
  `CLAUDE.md`; transcripts (`projects/`) are exported by `observe`. MCP
  contributions render as managed MCP servers and permission rules; skills
  are linked from `/opt/glove/cc` (`--add-dir`), outside the denied home.
  `search` bakes its SearXNG MCP server into the Claude Code image.
- Harness profiles may name `trusted_files` (relative to the working dir):
  files the harness loads its own config from, always bound read-only at
  ring 0 (a placeholder when missing; their directories pinned).
- `llm`: `auth: oauth` for a subscription token where the catalog allows it
  (`anthropic`, for `claude-code` only); catalog `headers` on every probe; a
  paginated model list is followed (`models_cursor`) and an alias matches its
  dated snapshot (`dated_aliases`). New provider `anthropic-compatible` (any
  Anthropic Messages API server, host/LAN/internet).
- Harness adapters may render read-only system config (`system_files`, a dir
  of its own under `/etc`, from `.glove/harness/`) and name the env var the LLM
  key travels in (`secret_env`). Every enforcer with a tool wrapper also renders
  `tool-wrapper.argv` (one argument per line). System files are rewritten in
  place (atomic per file), so a re-plan never swaps the dir a live session binds.
- `webfetch` for Vibe: a `fetch_url` MCP tool served over HTTP by a hardened
  `fetcher` sidecar (a port of Pi's web_fetch and its destination guard: public
  pages only, every redirect re-checked, policy refusals named; IPv4 in hex,
  octal or shortened form is refused, since Python does not normalise it as
  Node does; an unknown page charset falls back to utf-8). The harness
  reaches only the fetcher, never the egress proxy; with `observe` the fetcher's
  traffic goes through its own gate (`client: webfetch`, a new netgate client
  label).
- `webfetch` for Claude Code: its own `WebFetch`, allowed and pointed at the
  `proxy` endpoint (`HTTPS_PROXY` in the managed env, session forwarders in
  `NO_PROXY`); private destinations are refused by the egress layer. Without
  `webfetch`, `WebFetch` stays denied.
- Claude Code with `playwright`: the `tools` allowlist becomes allow rules and
  every other tool the pinned MCP defines (`all_tools`, a new neutral `mcp:`
  key) a managed deny rule, so Claude Code never offers it; host mode needs
  `i_accept_host_rce: true` as with Vibe.
- Extension networks take `when:` (like endpoints and images).
- **`github`** (with the new library **`relay`**): `gh`, and `git push`/`fetch`/
  `pull`/`clone`/`ls-remote`, from the agent's shell. Shims in the harness image
  relay each call to a hardened sidecar that holds the token (resolved in memory
  at `glove up`, never in the harness). The sidecar runs the real command under
  a policy:
  - gh: a subcommand allowlist; `auth`/`secret`/`extension`/… never; `gh api`
    GET only; github.com only.
  - git: network verbs to `https://github.com/<owner>/<repo>` remotes, with the
    repo's config defanged. `git clone <url> <dir>` hands git the checked,
    resolved `<dir>` itself, even when an option value (`-o <dir>`) spells the
    same word.
  - File arguments are opened inside `/work` only.
  - Traffic reaches GitHub's hosts only, through an in-process fence and then
    the egress. With `observe`, a gate labels the flows `client: github` (a new
    netgate client label).
  - A misbehaving client can't wear the sidecar down: requests waiting to
    start are capped (4× the concurrent limit, the rest dropped), a request
    left half-open holds no descriptors past 10s, and the fence drops a
    connection that sends no `CONNECT` within 10s.
- **`ssh`**: `ssh <host> <command>` to LAN hosts the session names, relayed to a
  hardened sidecar.
  - **Key:** held in an `ssh-agent` there, delivered by `launch_env` and never
    in the harness.
  - **Routes:** each host gets one forwarder on core's new `lan` network, the
    sidecar's only route. With `observe` it is a gate: `client: ssh` (a new
    netgate client label), `scope: lan`.
  - **Policy:** host keys checked strictly against the session's
    `known_hosts`; an option allowlist with no forwarding, jump hosts,
    ProxyCommand, identities or TTY.
  - **relay** gains `openssh-client` and `libnss-wrapper`, runs a relay with no
    `/work` (file arguments refused) and no fence when its policy names no hosts.
- `enforcer_options: {nono: {browsers: true}}` (`nono` and `nono+srt`): shell
  commands may start Playwright's baked Chromium, by granting the tool profile
  read-only `/proc`. Other processes' `environ`, `mem` and fd links stay closed
  (Landlock denies access to processes outside the command's own domain), so the
  harness's LLM key stays hidden; their command lines and `/proc/net` become
  readable. Off by default; the toolchains brief tells the agent which applies.
- Templates **`claude-code`** (Claude Code on an Anthropic subscription: `github`,
  WebFetch and a sidecar Chromium through `direct`, Python/uv and Node/pnpm with
  Playwright's Chromium usable from shell commands, `observe` + `filter`; `ssh`
  commented out) and **`vibe-search`** (`pi-search` with Vibe as the harness).
- Core: **`via: lan`** endpoints, a host:port the user named, dialled for a
  trusted extension's sidecar only, over a routable `lan` network that only
  those forwarders may join. The address must be a private IPv4 address
  (10/8, 172.16/12, 192.168/16) or a LAN name (one label, or under `.lan`,
  `.local`, `.home.arpa`, `.internal`): `lan` bypasses the egress provider, so a
  public host (or `host.docker.internal`) is refused.
- Validation patterns in core (extension, endpoint, alias and env names) and in
  `ssh` (host names, hosts, users) are matched whole (`fullmatch`), so a value
  with a trailing newline is refused at `glove check`.
- Core: **channels** (`channels:`), a session tmpfs volume at
  `/run/glove/<name>` shared by the harness and named sidecars, which every
  enforcer lets the harness and its commands write (no network). A relay uses
  files and FIFOs there because glove's seccomp below srt forbids Unix sockets.
  Also core: the **`work` privilege**, which binds the harness's whole `/work`
  read-write into one sidecar. Both are for in-tree or trusted extensions only.
- `github` sets `safe.directory=*` for git in the harness (`GIT_CONFIG_PARAMETERS`)
  and in the sidecar. On Docker Desktop, a checkout that was just made reads as
  root-owned inside the harness, so git refused it as "dubious ownership".

### Changed

- `privileges` no longer records empty `cap_add`/`devices` lists for a service
  that asks for neither.
- `search` for Vibe (and now Claude Code) is the `searxng` MCP server over HTTP
  from a hardened `searxng-mcp` sidecar (python slim + `mcp`, hash-pinned)
  instead of a stdio server baked into the harness image: one server for both
  harnesses, and the harness never reaches SearXNG itself. The raw SearXNG
  endpoint (`search`) is Pi's only.
- An extension's harness `env` value that renders empty is no longer set
  (`GLOVE_FETCH_ALLOW` outside `corporate`, `rag`'s `CLAUDE_OBSIDIAN_CORE`
  without a vault).
- **Harness plugins.** Pi, Vibe and Claude Code moved from `glove/harnesses/`
  and core's registry/render code to `harnesses/<name>/` (`harness.yml`,
  `adapter.py`, `image/`, `tests/`). Core loads a harness's adapter only when a
  session selects it and knows no harness by name (a test enforces it).
  `Config` has no default harness any more (session files always named one).
  Rendered Pi and Vibe homes, compose projects, policies and derived Dockerfiles
  are byte-identical (new golden tests, `tests/golden/harness/`), except that a
  baked skill's Dockerfile comment reads `(skill)`, which re-tags a session's
  derived image once when it uses `rag`.
- **Extension `harness:` keys are harness-neutral:** `vibe_mcp` → `mcp`
  (Playwright's allowlist key `enabled_tools` → `tools`), `pi_skills` →
  `skills`, `pi_extensions` → `pi: {extensions: [...]}`. Unknown keys are now
  refused. All bundled extensions are migrated; an out-of-tree extension using
  the old keys fails with "unknown key".
- Pi and Vibe images share one entrypoint (`glove/enforcers/entrypoint/`, the
  `gloveentry` build context) instead of two identical copies.

- Pi always starts as `/usr/local/bin/node /usr/local/bin/pi`, and Vibe's
  `pre_tool` hook always runs as `/usr/local/bin/python3 /opt/glove/vibe-hook`.
  The harness never depends on whichever `node`/`python3` is first on `PATH`
  (e.g. a `toolchains` runtime).
- Each enforcer now reports whether a browser can start in its per-command
  sandbox (`tools_run_browsers`), replacing a hard-coded list.
- Derived-image hashing prunes `node_modules`/`.venv`/`.git`/`__pycache__` while
  walking a staged directory instead of walking and then discarding them.
  `glove build` reuses the plan's rendered Dockerfile instead of rendering it
  again.

### Fixed

- `toolchains` (node): with no project, the global `packages` are linked into
  the pinned node's global require path, so `require('playwright')` works from
  a shell command in any directory (it needed `NODE_PATH` before). The brief
  says `mkdir -p "$TMPDIR"` only when `$TMPDIR` is set (srt sets it; nono
  doesn't).
- `llm` `location: internet` never connected: the forwarder carries the
  provider's hostname as an alias on the harness network, and Docker's DNS
  answers a container's own alias first, so it dialled itself. An aliased
  endpoint now dials through a second hop off the harness network
  (`glove-<id>-llm-out`). The cloud route is verified live with Anthropic.
- The `llm` launch probe retries a few times while nothing answers, so a gate
  forwarder (observe) still starting no longer fails the launch with "HTTP 0".

- Vibe's `sessions_subdir` is `logs/session`, where Vibe 2.x writes its
  transcripts (it never creates `sessions/`), so `glove up --resume` finds them.
- Vibe transcripts (`session_<ts>_<id>/messages.jsonl`) take their id from the
  folder, not the file name, so `glove up --session <id>` and the post-exit
  resume hint use Vibe's real id instead of `messages`.
- The `netobs-v3` fixture tests compare files only. `generate.py` writes empty
  `control/` folders that git can't carry, so the tests passed or failed
  depending on which folders a checkout happened to leave behind.

### Added

- **`toolchains`: `config_files` and `install_flags`** (per block, off by
  default), for projects that only install with their own settings (e.g. a
  committed `.npmrc` with `legacy-peer-deps = true`, without which `npm ci`
  fails with ERESOLVE).
  - `config_files: [.npmrc]` bakes extra files from the project directory
    beside the manifest and lockfile, before the install runs. Each entry must be
    a plain file name (no path), a regular file (never a symlink), and not already
    baked. Config files are public build inputs, so one with a credential-like
    key (`_auth`, `_authToken`, `npmAuthToken`, `password`, `token`, …, also as
    yarn v1's quoted `"//host/:_authToken" "…"`) or a URL with any userinfo
    (`user:pass@` or a bare token `https://ghp_…@host`; ssh's `git@` passes) is
    refused at plan time.
  - `install_flags: ["--legacy-peer-deps"]` appends flags to the project install
    for every manager (npm, pnpm, yarn, uv, pip). Each must be one long option
    (`--flag` or `--flag=value`, no whitespace or shell metacharacters) on the
    install mode's allow-list (nothing that moves the install, weakens the
    lockfile or TLS, or loads another config file), with no credentials in a URL
    value. Flags are shell-quoted and never apply to the global `packages`
    install.
  - Both feed the image tag. A block without them renders byte-identically (same
    Dockerfile, same tag). The integration script gains a lockfile that needs
    legacy-peer-deps, installed once via a baked `.npmrc` and once via the flag.
- **`toolchains`** (session file, off by default): version-pinned language
  runtimes and their packages, installed at image build time into the derived
  harness image so they work in the no-egress box. There are two handlers,
  `node` and `python`, and `lang` is a registry, so a new ecosystem is a new
  handler.
  - `node`: an exact `X.Y.Z` from the official tarball, SHASUMS256-checked, with
    `npm`/`pnpm`/`yarn` (Yarn 1.x only: `yarn@2+` is refused at plan time, since
    Berry isn't the npm `yarn` package), global `packages`, and Playwright
    `browsers` (installed by the project's `playwright` if it depends on one,
    else by the global one from `packages`).
  - `python`: a uv-managed CPython `X.Y[.Z]` (uv pinned by checksum) with a
    seeded venv (so `pip` is the venv's in every mode) via
    `uv sync --locked --no-install-project`, `uv pip` or `pip`.
  - A `project` contributes only its manifest and lockfile to the image (a
    symlinked one is refused), installed lockfile-strict by default. So the tag
    tracks those files, not the project's source, and source edits rebuild
    nothing. Layers run every block's runtime, then global tools, then project
    installs. Each step makes only what it wrote readable, with no blanket
    `chmod -R` layer. Everything lives under `/opt/glove/toolchains/`, never
    under a mount and readable by every enforcer with no policy change.
  - `PATH` comes from the image, `VIRTUAL_ENV`/`PLAYWRIGHT_BROWSERS_PATH` from the
    harness env (set if absent). There is no `NODE_PATH`, since nono strips it from
    wrapped commands; a node project's deps are linked into the pinned node's
    global folder (`<runtime>/lib/node`), so `require` resolves them from any
    directory under every enforcer.
  - Validated at plan time, so `glove check` fails early. The agent's context
    file gains a "Toolchains" section that explains the `/work` node_modules
    shadow and its symlink fix.
  - Known limit: Playwright engines start from a shell command under
    `enforcer: srt` but not under nono's per-command profile (`nono`, `nono+srt`).
  - Unset, nothing toolchain-specific renders. New integration script:
    `tests/integration/test_toolchains.sh`.
- **`corporate_ca`** (session file, off by default): a PEM bundle of a private
  CA (e.g. a TLS-intercepting proxy's) that the harness trusts on top of the
  public roots. It is validated at plan time (a path string naming a regular
  file with at least one PEM certificate and no private key, not the session
  file or `.glove/`), bound read-only at
  `/etc/glove/corporate-ca.pem`, and wired up with `NODE_EXTRA_CA_CERTS`.
  Node-based clients only; curl and Python keep the image's store. No enforcer
  policy change is needed (`/etc/glove` is already readable).
- **`playwright: {ca: <pem>}`** (sidecar modes): validated exactly like
  `corporate_ca` (one shared check, `glove/cafile.py`), then staged into the extension's
  state and bound read-only into the sidecar. The MCP trusts it through
  `NODE_EXTRA_CA_CERTS`, and `glove-pw-start` imports each certificate into
  Chromium's NSS db. The sidecar image gains `libnss3-tools`, so its tag
  changes. TLS verification is never disabled; tests assert that no bypass
  flag is rendered.

### Fixed

- `glove check`: when the plan fails, the extensions row resolves relative
  path settings against the session directory instead of reporting them as
  "must be an absolute path".

## [3.0.0] — 2026-09-29 — minimal core + extensions + session directories

A clean break from v2 (no automatic migration; v2 state is refused, not
guessed at). In short:

- **A session is a directory** (`glove new <template> <dir>`, `glove up`):
  `glove-session.yml`, `work/` and a private `.glove/`. `glove init/run`,
  `--name`, `~/.glove/envs/` and `~/.glove/homes/` are gone.
- **Minimal core + in-tree extensions**: `llm` (required), `vpn`, `tor`,
  `direct`, `corporate`, `search`, `webfetch`, `observe`, `filter`, `media`,
  `ocr`, `rag`, `playwright`, each validated and hardened by core, which never
  imports them.
- **Bundled templates** (`minimal`, `pi-search`, `pi-rag`, `browse-watch`,
  `corporate`) replace the separate template repositories.
- **`nono+srt` is the default enforcer on Docker** (`nono` on Podman); tool
  commands can no longer type into the harness under any enforcer.
- **Podman** is supported alongside Docker (srt enforcers refused there).

See "Upgrading from v2" in the README. The milestone sections below are the
detailed record.

### Cleanup (v3 M9)

- `glove rag fetch-model` validates its settings against the `rag` manifest,
  so it uses the manifest's `embed_model` default and pattern instead of its
  own copy. `glove playwright view` picks the runtime the same way
  `glove down` does.
- `glove up` asks the runtime for foreign subnets before taking the registry
  lock, renders the harness home once instead of twice, and `glove check`
  reuses the plan's composition for the extension doctor hooks.
- Internal: one helper each for session-scoped names (`glove/naming.py`),
  session-file host paths (`mounts.host_path`) and 0700 state dirs
  (`exports.ensure_dir`). Removed the unused `Config.rebuild`,
  `SessionPlan.env_id` and `build_session_plan(forwarder_image=)`.
  `SessionPlan.composition` is now always set.

### Review fixes (v3 M9)

- `glove down`/`rm` tear down under the runtime the session last ran with
  (`effective.yml`, else the session file), not whichever of docker/podman is
  on PATH. On a host with both, `rm` of a podman session no longer orphans its
  running containers.
- Extension harness env keys (manifest or `contribute` hook) must be plain
  variable names, and a hook's env can no longer silently overwrite another
  extension's. Endpoint/forwarder aliases must be hostnames. The Docker/Podman
  render refuses a harness env key that is not a plain name, and the
  merged-project re-check now also covers the harness's capabilities and
  `security_opt`.
- A malformed `~/.glove/config.yml` or an extension `cli.py` that fails to
  import no longer breaks every `glove` command. The broken CLI is skipped
  with a warning.
- `glove up` keeps what extensions resolved at plan time (e.g. corporate's
  routes) in `effective.yml`, next to the launch-time model.

### Release (v3 M9)

- The README leads with the session-directory workflow (install, quick start,
  templates, the session file, CLI), then extensions, the security rings and
  the support matrix, and gains an "Upgrading from v2" section. Links into
  git-ignored planning notes are gone.
- `docs/SECURITY.md` gains "Enforcers at a glance", one table comparing
  `nono+srt`, `nono`, `srt` and `none`.
- `vpn` verified live under `nono+srt` on Docker (`test_egress.sh vpn` 11/11,
  `test_observe.sh vpn` 27/27).
- **Fix: the bundled templates pinned `enforcer: nono`**, so a session made
  from one never got the Docker default. They now name no enforcer (a comment
  lists the choices): `nono+srt` on Docker, `nono` on Podman.
- **Fix: `glove check` failed for every session with `observe`** (`'dict
  object' has no attribute 'observe'`): its extension check composed the
  extensions without export roots. It now passes stand-in paths (nothing is
  created); covered by a unit test.
- Verified by migrating a real v2 pi-search instance (openai-compatible server
  on the LAN, `vpn` with a register hook, `search` groups, `observe`) to a
  session directory: `glove check` passes, and a live run under `nono+srt`
  brought up the tunnel (exit ≠ host), resolved the model and vision, and Pi
  answered with `web_search` + `web_fetch` through the VPN. Its v2
  transcripts, moved into the session, resolve with `glove up --session`.
- Package version 3.0.0 (was 0.2.0).
- Core size: 7.7k lines of Python (`find glove -name '*.py' | xargs wc -l`),
  above the ~5k the design aimed for; `extensions.py` (1044), `cli.py` (878),
  `compose.py` and `harnessconfig.py` (~430 each) are the largest.

### Enforcer: `nono+srt` (default on Docker), TIOCSTI fix, glove's srt `apply-seccomp` (v3 M8)

- **Security fix (every enforcer): tool commands can no longer type into the
  harness.** nono's base policy grants `/dev/tty`, so a shell command could
  inject keystrokes into the TUI (TIOCSTI; Docker Desktop's kernel allows it),
  e.g. answer a Vibe approval. Every tool wrapper now starts with
  `glove-pty notty`, which gives up the controlling terminal but keeps the
  process group (aborts still kill the command). `glove-pty` is a small static
  helper (`glove/enforcers/pty/`) baked into the harness images, which are now
  `glove/pi:0.5.0` and `glove/vibe:0.5.0` (rebuilt on the next `glove up`).
  `test_pi_nono.sh` 19 checks, `test_vibe_nono.sh` 13, on Docker and Podman.
- **`enforcer: nono+srt`, now the default on Docker** (a session file that
  names no enforcer; Podman keeps `nono`): srt (bubblewrap) wraps the harness
  process, nono wraps every shell command inside it. Every M8 spike gate
  passed on Docker, and every extension suite passes under it. srt makes
  `/work/.git/hooks`, `.git/config`, `.vscode`, `.idea`, `.envrc`, `.mcp.json`,
  `.gitmodules` and `.claude/{commands,agents,settings*.json}` read-only where
  they exist at launch, hides `.env`/`.env.*` under /work
  (`enforcer_options.srt.hide_env: false` turns that off), and puts the harness
  and its commands in their own PID namespace. The harness keeps the container
  network (ring 0 already limits it to the session's forwarders), so every
  extension works unchanged; srt's CLI cannot skip its network namespace, so
  glove runs srt's library through `glove-srt` (settings validated with srt's
  schema). The TUI runs on a pty relayed by `glove-pty` (srt starts it without
  a controlling terminal, so resize never reached it). Refused on podman (its
  compose provider can't apply the relaxed seccomp profile).
- **glove's `apply-seccomp`.** srt's stock filter leaves `unshare(CLONE_NEWUSER)`
  open under the relaxed `nested-userns` container profile, so a command inside
  srt could make a user namespace and mount (verified). The srt image now
  compiles srt's own `apply-seccomp.c` (pinned commit of v0.0.77) with glove's
  filter (`glove/enforcers/srt_image/glove-tighten.c`): no namespaces, no
  mounts, no `clone3`, plus srt's AF_UNIX and io_uring rules. srt uses it via
  `seccomp.applyPath`, for `enforcer: srt` too; the harness entrypoint refuses
  to start if it is missing (srt would silently fall back).
- **The srt image is an overlay** (`glove/enforcers/srt_image/Dockerfile`) on
  any harness image, tagged `<image>-srt-<hash of the overlay>` so an image
  built from an older layer is never reused. It brings srt, bubblewrap, socat,
  ripgrep and its own Node, so **Vibe can run srt** (before, its `-srt` image
  had no srt). The Pi Dockerfile's `GLOVE_ENFORCER` build arg is gone.
- `tests/integration/test_nono_srt.sh [pi|vibe]` (29 live checks, incl. no
  files appearing in `work/` during the session; `RT=podman` checks the
  refusal); `test_pi_srt.sh` gains a user-namespace check (12). The egress,
  observe, playwright and corporate scripts take `ENFORCER=`.

### Browser: `playwright` headless and noVNC sidecars, `browse-watch` template (v3 M7)

- **`playwright` gains `mode: headless` (now the default) and `mode: novnc`.**
  Chromium + the Playwright MCP run in a sidecar built from
  `mcr.microsoft.com/playwright:v1.63.0-noble` (pinned by digest) with
  `playwright-core@1.63.0` installed from a committed lockfile (the one pin;
  host mode reads it too). The sidecar is alone on an internal `browser-net`
  with two forwarders: `browser` (the harness's way in) and `browser-egress`
  (its way out, to the egress proxy; with `observe`, a gate labelling flows
  `client: playwright`). No ports, no CDP port, no DNS, no default route. The
  MCP config (timezone, locale, the WebRTC no-UDP flag) is rendered by glove
  and mounted read-only. Settings: `tools`, `profile` (`ephemeral` |
  `session`; refused under Tor unless `allow_persistent_profile_with_tor`),
  `viewport`, `timezone`, `locale`, `chromium_sandbox`, `downloads`/`uploads`
  (`work` opt-ins), `resources`, and for novnc `allow_control`, `clipboard`.
  The sidecar mode needs an egress extension.
- **Chromium's sandbox is on**, with a new core seccomp profile
  `chromium-userns.json` (generated by `make_profile.py`: default +
  unconditional `clone`, `clone3`, `unshare`, `chroot`). Probed live: "sandbox
  ok" with it; "Chromium sandboxing failed!" with the default profile; a crash
  without `chroot`. A new hardening row refuses it on the harness. The sidecar
  probes the sandbox at every start and exits with guidance if Chromium cannot
  use it, so `glove up`'s verify fails closed instead of the first page load.
- **`novnc`**: TigerVNC + websockify on the sidecar's loopback only;
  `glove playwright view [--control] [--no-open]` serves noVNC through a
  per-command loopback listener piped over `docker|podman exec … socat`,
  refusing any foreign `Host`/`Origin`. The two VNC passwords are generated in
  the sidecar's tmpfs at each start (the handoff's compose secrets are not
  possible on a read-only container). View-only and the clipboard are enforced
  by the VNC server. `glove playwright status`.
- **Host mode**: MCP and CDP ports are free loopback ports picked at the first
  launch and kept per session (`.glove/ext/playwright/host-ports.json`;
  `port`/`cdp_port` pin them); refused behind an anonymising egress (`vpn` and
  `tor` now export `anonymising: true`).
- **Vibe gets the tool allowlist**: an extension's `vibe_mcp` entry may carry
  `enabled_tools`, rendered as one Vibe `disabled_tools` regex that hides every
  other tool of that server (Vibe's global `enabled_tools` would hide its own
  tools). `browser_run_code_unsafe` is no longer offered to Vibe in any mode;
  Vibe + host mode still needs `i_accept_host_rce: true`.
- **Pi**: the browser extension closes its MCP stream on `session_shutdown`;
  before, `pi -p` with the browser never exited.
- **Template `browse-watch`** (new): Pi + an egress + `playwright: {mode:
  novnc}`. `pi-search` gains a commented `playwright: {}`.
- **Core**: `images:` entries take `when:` (host mode builds no sidecar image);
  `limits:` are templated; a trusted extension's sidecar may bind a named
  subdirectory of `work/` (`{{ work }}/<dir>`), never `work/` itself; a sidecar
  seccomp exception the runtime cannot apply is refused with the extension's
  `hint` instead of dropped (Podman); `glove check` renders the project in
  memory, so render-time refusals show before `glove up`.
- **Verified live** (`tests/integration/test_playwright.sh
  headless|novnc|control|vibe`): Docker 20/23/23/14 (sandbox on), Podman
  19/22/22/13 (`SANDBOX=off`); Chromium's background destinations seen through
  the gate: accounts.google.com, clients2.google.com, update.googleapis.com,
  www.google.com. **Untested:** behind vpn/tor/corporate (direct egress only),
  host mode's host-side start, noVNC over a real display by a person (the
  tunnel, auth and input were verified by script).

### Documents: `ocr` and `rag` extensions, `pi-rag` template (v3 M6)

- **`ocr`** (new): tesseract (+ `languages:` packs), ocrmypdf, poppler,
  ghostscript and `file` in the harness image, and `glove-ocr FILE`: an image's
  text, or a PDF page by page (text layer where there is one, OCR where not;
  `--pages`, `--lang`, `--dpi`, `--force-ocr`, `--json`). No `--vision`: a shell
  command has no network, and llama_index's `image_vision_llm` is a local
  BLIP-2 (torch), not the session's model. The brief follows the model's
  vision capability. Fixtures (PNG, scanned PDF, text-layer PDF) and their
  generator in `extensions/ocr/tests/fixtures/`.
- **`rag`** (new, requires `ocr`): kstore from the `glove-pi-rag` template,
  baked in with pinned llama-index-core 0.14.25, llama-index-vector-stores-faiss
  0.7.0, llama-index-readers-obsidian 0.8.0, fastembed 0.8.1, faiss-cpu 1.15.1.
  `models_dir` (required) and `obsidian_dir` (optional) are read-only mounts;
  skills `rag-parse`/`rag-query` (+ claude-obsidian's offline skills when
  mounted); `glove rag fetch-model` replaces `fetch-embedding-model.sh`.
  kstore changes: `KSTORE_*` env (was `PIRAG_*`); images are OCR'd by `sync`;
  a scanned PDF's citations name the original input, not the OCR'd cache copy;
  llama_index's MockLLM notice no longer lands on stdout (it broke `ask --json`);
  onnxruntime's load-time `/sys` probe errors (denied by the tool sandbox) are
  held back unless loading fails.
- **Template `pi-rag`** (new): llm + ocr + rag + media, no egress provider.
  `pi-search` gains `ocr: {}` (its apt stopgap is gone).
- **Extension API** (core):
  - `mounts: {<name>: {setting: <path setting>}}`: a read-only harness bind at
    `/mnt/<ext>-<name>` of a directory the user named; the setting may not have
    a default; the same private-path guard as the session's `mounts:` (shared
    `sessiondir.exposes_private`); `mount.<name>` in templates.
  - `harness.pi_skills`: baked (`skills/x`, needs a `SKILL.md`) or from a
    mount (`{mount, path}`, skipped when the mount is off); listed in Pi's
    `settings.json` ahead of the session's own `skills`.
  - `pip` layers work on Pi (Debian's pip3, bootstrapped once, PEP 668 flag).
  - List settings take a per-item `pattern`; rendered `apt`/`pip`/`npm`
    entries split on whitespace, so a template can expand a list setting.
  - Two image sources that would stage under one name are refused (they
    silently overwrote each other).
- The LLM stub logs the skill directories in Pi's system prompt (`skills=`).
- **Verified live** (`tests/integration/test_rag.sh`, Pi): 13/13 on Docker and
  on Podman (with a claude-obsidian mount), and 12/12 on Docker from a cache
  `glove rag fetch-model` had just filled. Regression: `test_session_dir.sh`
  10/10 on both. **Untested:** `ocr`/`rag` with Vibe.

### `vpn` verified live on Docker and Podman (v3 M5 follow-up)

- **Compose secrets now mount at `/run/glove-secrets/<name>`** (was
  `/run/secrets/`). Podman's default `mounts.conf` mounts its subscription
  directory over `/run/secrets` at container start, hiding the files compose
  had copied in: on Podman gluetun saw no WireGuard key and restarted in a
  loop. Fragments get the path as `session.secrets_dir`; the `vpn` fragment
  points gluetun's `*_SECRETFILE` variables at it.
- **New sidecar privilege `low_ports`**: `net.ipv4.ip_unprivileged_port_start=0`
  in the sidecar's own network namespace (Docker's default for every
  container; Podman's is 1024). gluetun declares it: on Podman its DNS server
  could not bind `:53`, so the gates' in-tunnel resolver fell back to
  `unavailable`. Preferred over granting `NET_BIND_SERVICE`.
- **gluetun's healthcheck is stated in the fragment.** The image is an OCI
  manifest, whose config has no healthcheck field; Podman drops it (Docker
  keeps it), so `verify vpn/tunnel-up` found no healthcheck.
- `test_observe.sh` takes a `vpn` route (same `VPN_SETTINGS`/`VPN_LOCAL` as
  `test_egress.sh vpn`) and `KEEP=1` leaves the stack up for inspection.
- **Verified live**, WireGuard via a register hook with Keychain references:
  `test_egress.sh vpn` 11/11 and `test_observe.sh vpn` 27/27 on both Docker and
  Podman. **Untested:** OpenVPN, gluetun's built-in providers (no account here).

### Network observability as extensions: `observe` / `filter`; `corporate` egress (v3 M5)

- **The netgate moved out of core** into extensions: the **`gate`** library
  (container code + image, host-side `gatelib`), **`observe`** (the read
  grant) and **`filter`** (the write grant). `glove/netgate/`, `observe.py`,
  `netview.py` and `netrules.py` are gone from core (~10.7k → ~7.3k lines).
- **Core API:** a `forwarder` slot (its provider's `forwarder` hook replaces
  the socat behind any endpoint; core names, networks and hardens the result),
  **export roots** (`~/.glove/observe/<id>/` for in-tree `observe`,
  `~/.glove/control/<id>/` read-only for the gates only while in-tree `filter`
  is active; checked by path), `interpose: true` endpoints (an egress
  consumer's hop, rendered only when a forwarder provider is present),
  `address` endpoints over `wan` for the egress provider, `libs` images of
  required library extensions, extension CLIs (`cli:` → `glove <name> …`,
  listed by `glove ext`), contributed verify items, and the `http-refused`
  verify kind.
- **observe** (`extensions: {observe: {...}}`, replacing the top-level
  `observe:` key): every endpoint's forwarder is a netgate; the collector
  (`network_mode: none`) writes `~/.glove/observe/<id>/net/`. **Transcripts**
  (`transcripts: true`, default) are bound from `observe/<id>/transcripts/`
  over the harness's transcript directory (Pi `.pi/agent/sessions`, Vibe
  `.vibe/logs/session`); `glove up --resume` finds them. Proxy gates take the
  route, in-tunnel resolver and guard exceptions from the egress provider.
  **SearXNG gets its own gate** (`searxng-egress`, `client: searxng`) and leaves
  the egress network, so its only route to the proxy is observed.
  `glove observe status|flows` replaces `glove net status|flows`.
- **filter** (requires observe): creates `control/<id>/`, mounts it read-only
  into every gate and the collector, passes `--rules`, and records
  `grants.filter = {granted: true, since}`. `glove filter
  block|unblock|rules|validate` replaces `glove net …` and never creates the
  directory. **Observe alone never reads rules** (no mount, no `--rules`, no
  directory; invariant tests). Removing `filter` revokes it at the next
  `glove up`: `rules.json` → `.glove/ext/filter/rules.revoked.json`, the
  directory is removed, `granted: false`, and the collector stops reporting
  `rules` in `status.json`.
- **`corporate`** (new egress provider, template `corporate`): a netgate proxy
  with `--upstream direct` that resolves destinations itself (`dns: host`
  follows the VPN's split DNS), checks the resolved address, applies a static
  default-block policy from `allow_domains` / `allow_cidrs` / `from_interface`
  (the host's routes via a VPN interface, from `netstat -rn`, shown in `glove
  plan` and stored in `effective.yml`), and dials that address. The allowlist
  is the SSRF guard's exception list (session file only; never `rules.json`)
  for this gate, observe's gate in front of it and `web_fetch`. The host
  gateway, metadata, loopback and the session's own network stay refused.
  Raw TCP endpoints: `tcp: [{name, to}]`. Verify: `https://example.com` refused
  (`http-refused`), optional `probe_url` answers. `route: corporate`.
- **Gate 0.2.0:** guard exceptions (`--guard-allow-host/-cidr`, `--deny-cidr`),
  the `direct` upstream, and a refusal's reason relayed through a chained gate.
  `web_fetch` now tells the agent when a request was **refused by policy**
  (with the gate's reason) instead of reporting a network failure.
- **Grants** in `session.json` and the registry row follow the Layman handoff:
  `{"observe": {"net", "transcripts"} | null, "filter": {"granted", "since"} |
  null}`. New fixtures: `tests/fixtures/netobs-v3/` (observe-only,
  observe-filter, observe-no-transcripts, filter-revoked, orphaned,
  not-observable), generated by `extensions/observe/tests/fixtures/generate.py`.
- **tor** is also on the internal egress network, so observe's gates resolve
  names in-tunnel over its SOCKS port (never the harness network).
- **Podman:** every sidecar that must be the session uid runs `keep-id` (a
  rw host bind, or a shared tmpfs volume such as the netgate events socket),
  and glove starts sidecars one `compose up` at a time there (Podman 6.1 gives
  concurrently started keep-id containers a one-entry id map; compose's
  `--parallel` does not serialise starts). Forwarders listening below 1024 get
  `net.ipv4.ip_unprivileged_port_start=0` in their own netns (Docker's default;
  Podman's raw-TCP/443 forwarders could not bind before).
- **Fail closed:** a failed `compose up` of the sidecars now stops them too
  (before, a half-started egress stack could be left running).
- Removed from core: `Config.services`/`net`/`observe`, `Service`, the v2
  `net` profiles (`lan`/`internet`/`docker:`), and the harness host-gateway
  hardening row (structurally impossible now). Old `effective.yml` files with
  those keys still load.
- Tests: the netgate suites moved to `extensions/{gate,observe,filter}/tests/`;
  new invariant tests (observe-only gates never see rules; `rules.json` cannot
  carry guard exceptions; export-root ownership; the forwarder hook contract),
  direct-mode and corporate tests. Live: `test_observe.sh [direct|tor]` and
  `test_corporate.sh` replace `test_netgate_m1/m2.sh`;
  `netgate_control_perms.sh` and `test_netgate_shutdown.sh` use the v3 layout
  (the perms probe now asks the runtime whether SELinux is on).
- **Verified live on Docker and Podman:** observe+filter over direct 25/25 and
  over tor 26/26 (incl. in-tunnel resolution); corporate 11/11; perms 6/6;
  shutdown 9/9; M3/M4 regressions (session dir 10/10, nono Pi 16/16, egress
  direct/tor 11/11). **Untested:** `corporate` through a real corporate VPN;
  the vpn route (still waiting on the operator's run).

### Egress, search and web fetch as extensions (v3 M4)

- **Egress providers** fill the exclusive `egress` slot: **`vpn`**
  (gluetun; WireGuard or OpenVPN; any gluetun provider or `custom`), **`tor`**
  (tor + privoxy, built from pinned Alpine; `exit_nodes` optional) and
  **`direct`** (tinyproxy; no tunnel, `route: direct`). Only the provider's
  tunnel container joins the routable `glove-<id>-wan`; consumers sit on the
  internal `glove-<id>-egress`, so egress fails closed by topology.
- **Verify kinds (core):** `container-healthy`, `tcp-open`, `http-ok`,
  `exit-ip-differs`, run from throwaway hardened containers on session networks
  after the sidecars start and before the harness. A failure prints the
  sidecar's last log lines (credential lines withheld), stops the session's
  sidecars and aborts `glove up`. An extension's `diagnose` hook explains it
  (vpn: a dead WireGuard handshake via tun0's byte counter).
- **Launch-time hooks:** `materialize` (write extension state under
  `.glove/ext/<name>/` at `glove plan`/`up`, never `check`) and `launch_env`
  (host-side, in memory: the **vpn register hook** in the session's `local/`
  gets account credentials on stdin and returns a fresh WireGuard key, which
  goes to gluetun as a compose secret). Sidecars that mount a compose secret are
  recreated on every `glove up`, so a rotated key always takes effect.
- **`search`** now runs SearXNG + valkey in the session (valkey on a private
  network). Settings are rendered from the v2 pi-search `configure.py` (engine
  groups `blocks_tor`/`requires_license`/`phones_home`/`security_mode`,
  per-engine `enable|disable`, route-specific base). Every engine request goes
  through the egress proxy. Requires an egress provider; the interim `host_port`
  setting is gone.
- **`webfetch`** (new): Pi's `web_fetch` through a `proxy` forwarder to the
  egress provider. Its npm dependencies are pinned and baked into the image.
  It refuses non-public destinations (IP literals, local and single-label
  names, credentials) and checks every redirect hop. `direct`'s tinyproxy
  refuses the same shapes.
- **Template `pi-search`** (`glove new pi-search <dir>`): llm + vpn (tor/direct
  one line away) + search + webfetch + media.
- `glove check` now checks every secret-type setting that is set (e.g.
  `vpn.register_user`), still without reading any value.
- **Podman:** `userns_mode: keep-id` is now applied only to containers that
  write a host bind (the harness, the netgate collector, an extension sidecar
  with a rw bind). Forwarders and other sidecars keep an unprivileged subuid.
  Found live: Podman 6.1.2 intermittently gave concurrently started keep-id
  containers a one-entry id map ("doesn't map GID 20").
- Verified live on Docker and Podman: `tests/integration/test_egress.sh
  tor|direct` (11 checks: verify incl. `exit-ip-differs`, only the provider on
  `wan`, no direct internet for SearXNG or the harness network, search/proxy
  endpoints, Pi `web_search`/`web_fetch` driven by the stub, refusals), and two
  sessions concurrently (two tor on Docker; tor on Docker + tor on Podman).
  **Untested:** a live `vpn` tunnel (gluetun's hardened start was verified with
  a dummy peer; `test_egress.sh vpn` needs the operator's VPN) and OpenVPN.

### A session is a directory (v3 M3)

- **Breaking: the v2 environment model is gone.** `glove init`, `glove run`,
  `glove config`, the bare `glove <harness>` form, `--env`, `--name`,
  `--config`, `--workdir`, `--add-dir`, `--net`, `~/.glove/envs/` and the
  registry's `home` field are removed (no compatibility shims).
- **`glove new <template|path|git-url> [dir]`** materializes a session:
  `glove-session.yml` (schema v3, `glove: 3`), `work/` (→ `/work`) and `.glove/`
  (`0700`, with a `.gitignore` of `*`): `id` (`<dirname>-<6 hex>`, sanitised so
  it is a valid compose project and Layman `SAFE_NAME`), `compose.yml`,
  `effective.yml` (now also recording launch-time resolutions such as
  `model: auto`), `baseline.yml`, `home/`, `enforcer/`, `ext/<name>/`.
  Templates are materialized copies; `glove check` warns when a template changed
  and `glove new --diff` shows the change. Bundled template: `minimal`.
- **New commands:** `glove check` (schema, remaining `<set-me>`s, secret
  references exist without reading them, doctor + extension checks), `glove plan`
  (render and show the grants, incl. the last launch's resolved model),
  `glove up` (`--resume`/`--session` work from `.glove/home`), `glove down`,
  `glove rm [--all]`, `glove ls` (ok/missing/stale), `glove ps`, `glove gc`,
  `glove policy`, and `glove keychain set <service>` (prompts; the secret never
  appears in argv). Session commands find the nearest `glove-session.yml` at or
  above the current directory.
- **Registry v2** (`{"v": 2, "sessions": [{id, dir, harness, template, created,
  grants, subnet}]}`, written atomically). A v2-era registry (a JSON list) is
  refused, never overwritten. A moved session keeps its id and the registry
  follows it; a copied one is refused until it gets its own id.
- **Per-session subnets:** each session gets a /24 from `subnet_pool`
  (`~/.glove/config.yml`, default `172.31.0.0/16`) and each of its networks a
  /27. Allocation avoids other sessions and the runtime's existing networks, and
  `glove up` re-allocates when a foreign network has taken the range.
- **Mount safety:** `mounts:` (relative paths resolve against the session dir)
  may never expose `.glove/`, `local/`, `glove-session.yml`, glove's home or
  another registered session's state.
- **Network-observability paths** move to their v3 locations:
  `~/.glove/observe/<id>/net/` and `~/.glove/control/<id>/rules.json`
  (`env` = `session` = the id); `session.json` and registry rows carry `grants`.
  `glove net …` selects the session by directory (`--dir`).
- `docs/examples/*.glove-session.yml` replace the v2 `*.glove.yaml` presets.
- Integration scripts run on session directories (`tests/integration/
  lib_session.sh`); new `test_session_dir.sh` covers the lifecycle live.
  `test_netgate_m1.sh`/`test_netgate_m2.sh` still use v2 config keys and exit
  with SKIP until they are rewritten for the gate/observe extensions (v3 M5).
- **Podman:** the session-dir lifecycle and the nono/Vibe/ring-0 integration
  scripts take `RT=podman` and pass on Podman Desktop (macOS, rootless), also
  while Docker Desktop runs sessions at the same time. An unsupported
  runtime/enforcer pair (srt on podman) is now a clean error, not a traceback.

### Extensions and the `llm` inference slot (v3 M2)

- **Extension API (`api: 1`).** Capabilities are directories under
  `extensions/<name>/` with a declarative `extension.yml`, selected per session
  in `extensions:` (name → settings). Core (`glove/extensions.py`,
  `glove/compose.py`) validates typed settings (unknown keys, `<set-me>`
  placeholders and literal secrets are errors), fills exclusive slots
  (`inference` required, `egress`, `browser`), expands `requires` (auto-adding
  `auto: true` libraries), checks `conflicts` and `validate` rules, orders
  extensions topologically, and renders every contribution through a sandboxed
  Jinja context that sees only `settings`, `session`, `slot`, `endpoint`,
  `names`, the extension's own `state` dir and `assets`.
- **Sidecar invariants (§3.4), enforced by core.** A fragment may only hold
  `services`/`volumes` with allowlisted keys; core injects the hardening set
  (non-root, `cap_drop: ALL`, `no-new-privileges`, read-only rootfs, seccomp,
  `ipc: private`, pids/memory limits) and applies only `privileges:` drawn from
  an allowlist (`NET_ADMIN`, `NET_RAW`, `CHOWN`, `SETUID`, `SETGID`,
  `DAC_OVERRIDE`; `/dev/net/tun`; core-owned seccomp profiles by name). Images
  must be pinned by digest or built by the extension. No ports, no host
  namespaces, no `docker.sock`, no host binds outside the extension's session
  state (assets read-only), never the harness network; only the egress provider
  joins `wan`. The merged project is re-validated before it is written.
- **Out-of-tree extensions** load from `extension_paths` in the new
  `~/.glove/config.yml`, are labelled out-of-tree, cannot shadow an in-tree
  name, and get no privilege exceptions, host ports or host services unless
  listed in `trusted_extensions`.
- **`llm` extension** (required `inference` slot) with a provider catalog
  (`openai-compatible` as the default for any OpenAI-API server, plus llama.cpp,
  ollama and LM Studio for their native capability probes, and openai, anthropic,
  mistral and openrouter as cloud endpoints) and `location: host | lan | internet` routing, each
  rendering exactly one `glove-<id>-llm` forwarder. Core keeps only a
  provider-neutral `ModelDescriptor` rendered into Pi `models.json` (vision →
  `input: ["text","image"]`, `contextWindow`, `maxTokens`, `reasoning`) and Vibe
  `config.toml`. `model: auto` / `capabilities: auto` are resolved at launch
  from a throwaway hardened container on the harness network. Explicit
  `capabilities:` keys merge with the probe (explicit wins); a capability the
  server doesn't report prints a warning naming the default used. Verified
  live: `location: host` against a stub llama-server (`model: auto`, vision and
  `n_ctx` resolved), and `location: lan` against a real NInfer server as
  `openai-compatible` with `capabilities: {vision: true}` (`model: auto` →
  the served model, key passed by Keychain reference, Pi answered through the
  forwarder under nono).
- **Pi with a keyless server works.** Pi refuses a provider with no `apiKey`;
  keyless servers now get the fixed non-secret placeholder `glove-no-key`.
- **Ported to extensions:** `media` (image layers), `search` (harness side:
  Pi extension, Vibe MCP, `SEARXNG_URL`; SearXNG itself is still external until
  M4) and `playwright` `mode: host` (from `plugins/browser`). Extension image
  layers and Pi extensions compose into a content-addressed derived image.
- **Removed (clean break, D6):** `glove/plugins/`, `plugins:`/`plugin_options:`,
  top-level `browser:`, `--with`, `--browser`, `model`, `llm_service`,
  `llm_api_key`, `host-server`, the `render_compose` shim, the
  `{media_dir}`/`{chrome_profile}` host-service tokens, and the legacy
  plugin bridges. `docs/examples/` are rewritten for `extensions:`.
- The netgate records the llm forwarder's scopes `lan`/`cloud`; `rules.json`
  v1 still accepts only `local|tunnelled|direct` (unchanged for Layman).

### Security (v3 M1 — also applicable to v2)

- **srt no longer leaks the LLM key to tool commands.** The srt settings had no
  `credentials` section, so `env` in a tool command showed `GLOVE_LLM_API_KEY`.
  glove now renders `credentials.envVars` with `mode: deny` for the LLM key and
  every passthrough secret. srt takes exact names only and unsets each one with
  bwrap `--unsetenv`. Verified live: `env` in a tool command lacks the key. Also
  verified: a tool command can't read the harness's `/proc/<pid>/environ` in
  weak mode (the kernel refuses it across the user namespace; the PIDs are
  still visible) or in strong mode (separate PID namespace), so `srt.nested:
  strong` is not required for this.
- **srt `allowUnixSockets` removed.** It was rendered at the top level, where
  srt silently drops it. In srt it is a macOS-only `network` key and is ignored
  on Linux anyway, because srt's seccomp filter blocks new AF_UNIX sockets.
- **Ring-0 read-only binds over files the host later runs or trusts.**
  `.git/hooks`, `.git/config` and an in-tree `core.hooksPath` in every rw mount
  are read-only. `.git` is re-bound so renaming it fails with `EBUSY`; without
  that, `mv .git x && git init` would bypass the binds, which the live test
  showed. `protect_ide_files: true` does the same for
  `.vscode`/`.envrc`/`.mcp.json`, using empty placeholders when missing. New
  `tests/integration/test_ring0_protect.sh` (15 checks, harness and tool
  commands).
- **Every socat forwarder is hardened.** Only netgate forwarders had the sidecar
  hardening set. Plain forwarders now run non-root with `cap_drop: ALL`,
  `no-new-privileges`, a read-only rootfs and pids/memory limits.
- **Browser fixes.**
  - `host-mcp` + Vibe is refused unless `browser.i_accept_host_rce: true`.
    Vibe gets every MCP tool, including `browser_run_code_unsafe`, which is
    code execution on the host.
  - The host MCP is pinned to `playwright-core@1.63.0 mcp` (it was
    `@playwright/mcp@latest`).
  - `host-server` passes `--path /<random>`. The `--ws-path` flag doesn't
    exist, so the server couldn't start.
  - The host Chrome profile is per session (`<session>/chrome-profile`), and
    Chrome stops on `glove down` unless `browser.keep_browser: true`. A kept
    Chrome would own `:9222` and be reused by the next session.
- **Pins bumped.**
  - nono 0.75.0 → 0.78.0, pinned by tag and digest in both Dockerfiles. 0.78.0
    fixes five GHSAs, all in features glove doesn't use (packs, tool-sandbox,
    proxy L7 path policy). Its removed profile aliases don't affect glove's
    keys.
  - srt 0.0.75 → 0.0.77, which adds the resolved-address DNS-rebinding guard.
- **Hooks aligned.** The Vibe hook wraps commands with `bash -c` (non-login)
  like Pi's. A login shell sources `/etc/profile`, which nono denies.

### Development

- **Core/extension import boundary (v3 M0).** New top-level `extensions/`
  package for in-tree extensions, and an [import-linter](https://import-linter.readthedocs.io/)
  contract (`[tool.importlinter]` in `pyproject.toml`) forbidding `glove` from
  importing `extensions`. Run it with `uv run lint-imports`; `tests/test_layering.py`
  runs it in the unit suite and checks that the contract really catches a
  forbidden import. Lint now covers `glove extensions tests`.

## minimal core + opt-in plugins

Reworking glove into a tight, minimal sandbox with every optional capability
behind an off-by-default plugin system (design note:
`docs/planning/minimal-core-plugins-designnote.md`). Landing in phases; the
default (no-plugins) path stays fully working at each step.

### Features

- **`llm_api_key` can reference the key instead of containing it.**
  `keychain:<service>` reads a macOS Keychain generic password and
  `env:<VAR>` reads the environment. glove resolves the reference in memory at
  launch, before any host service starts, so a missing key fails early. Planning
  and `--dry-run` use only the variable name and never read the Keychain. The
  effective config keeps the reference (it is not a secret); a literal key is
  still redacted there. With a reference, no file on disk holds the LLM key.
- **The LLM API key is stored only in your config.** It was also written in
  cleartext into each session's `docker-compose.yml` and Pi's `models.json`. The
  compose file now declares `GLOVE_LLM_API_KEY` with no value, glove passes the
  key in the environment of `compose up`/`run`, and `models.json` says
  `"apiKey": "$GLOVE_LLM_API_KEY"` (resolved by Pi). This also removes a latent
  bug: Pi runs an `apiKey` that starts with `!` as a command and expands one
  that starts with `$`. Verified live on Docker Desktop: Pi under nono sent
  `Authorization: Bearer <key>` through the `llm` sidecar. The next `glove run`
  of an existing session rewrites both files.
- **glove owns its home's layout; Layman creates nothing** (answers
  `docs/planning/layman-independence.md`; results in `…-results.md`).
  - **`~/.glove/control/` always exists with the home.** Whenever glove
    creates its home (`glove init`, `glove run`, any registry write) it also
    creates `control/` as the invoking user (`0777 & ~umask`), and `glove
    init`/`run` add it to an older home. glove warns, with the `sudo chown`
    fix, when `control/` is someone else's, and a gated render names the
    foreign parent directory it cannot create a rules directory in.
  - **Ownership contract simplified:** a second writer sets its `rules.json`
    temp file to `0644` and does not `chown` it. The directory is `0700`, so
    nobody else can reach it. The chown-and-`0600` form still works. The
    launch warning now says "readable by you: mode 0644, or owned by you".
  - SELinux hosts remain unsupported, for glove sessions and for Layman; the
    README says so.

- **Network observability: Layman follow-up** (answers
  `docs/planning/network-observability-layman-followup.md`; results in
  `…-followup-results.md`). All changes are additive to the frozen v1 schema,
  or bug fixes that make glove do what the handoff already said.
  - **Security fix: an unreadable `rules.json` no longer fails open.** Any
    `stat`/read error other than "does not exist" (e.g. `EACCES` on the file or
    its directory) was treated as "no rules", with `ok: true`. It is now a
    rejection: the last known-good set stays enforced, and `status.json` says
    `ok: false`, `error: "cannot read rules.json: permission denied"`. A
    `chmod`/`chown` repair is picked up without a rewrite. `glove net
    rules|block|unblock` report the same error instead of crashing.
  - **Ownership contract for `control/`.** The gate already runs as the
    invoking user's uid:gid; the handoff now says what a second writer must do
    (chown its temp file to the directory's owner, `0600`, never create the
    directory). `glove run` refuses, with the fix, a control directory it cannot
    `chmod`, and warns when an existing `rules.json` is unreadable. Verified
    live on Docker Desktop (macOS) and on rootless and rootful Podman (SELinux
    enforcing); rootful Docker on Linux is untested
    (`tests/integration/netgate_control_perms.sh` is the probe).
  - **Confirming a write:** `status.json` `rules.sha256` (the enforced file)
    and `rules.last_rejected` `{checked_at, source_mtime, sha256, error}`.
    `glove net rules` shows whether the file on disk is enforced, rejected or
    pending.
  - **Gate lifecycle:** flow records carry `run` (the forwarder process), and
    `flows.ndjson` gets `type: "gate"` start/stop records. Forwarders
    re-announce every 10 s; the collector writes an inferred `stop` for one
    silent for 30 s. `glove net status` counts unclosed flows of ended runs as
    cut, not active. Verified live with Docker Compose: `glove down` loses no
    closes; a `docker kill`ed forwarder (not restarted by `unless-stopped`) gets
    its inferred stop (`tests/integration/test_netgate_shutdown.sh`). A `stop`
    ends only its own run: a crashed forwarder's late inferred stop no longer
    marks its restarted replacement ended (which misreported the replacement's
    idle open flows as cut), and the collector stops tracking a run once a new
    run of the same service starts, so it doesn't write that late stop at all.
  - **`glove net validate <file|-> [--env] [--session TOKEN] [--json]`**: the
    gate's validator, pure, exit 0/1.
  - **Fixtures:** `tests/fixtures/netobs-scenarios/`, 16 complete `net/`
    directories from the real gate code, one per §6.1 state the original
    fixture lacks. The original `tests/fixtures/netobs/` is pinned byte-for-byte.

- **Network observability, milestone M5: the whole chain, record: full,
  retention.**
  - `harness: false` services: a listener joined only to its `join_network`,
    never the harness's network, and never offered to the harness. Connections
    are labelled `observe.client` (`searxng | playwright | unknown`).
    glove-pi-search's branch adds a SearXNG fan-out listener and re-points
    SearXNG at it, so one `web_search` shows every engine contacted.
  - `observe.record: full`: `request: {method, url}` for cleartext HTTP
    (`url: null` for CONNECT). `record_headers` adds headers with credentials
    redacted. A loud launch warning.
  - `observe.retain`: time-based rotation (every retain/4) and expiry; the
    current exit record is carried forward so retention never drops present
    state. `glove down --wipe` also deletes the flow and exit record.
  - Empty and idle proxy connections are recorded as `eof`/`timeout` with
    `verdict: allow`, not as malformed-request blocks.
  - **Verified on live glove-pi-search** (vpn). One agent `web_search` produced
    flows to nine distinct engine hosts, all `searxng` / `search-engine-fanout`
    / `tunnelled` with in-tunnel IPs. SearXNG's only TCP peers were the gate and
    valkey. Search results and latency through the gate matched direct-to-gluetun,
    warm and cold. `record: full` captured a cleartext request with `Cookie`
    redacted. Retention rotated and expired files and kept the current exit.

- **Network observability, milestone M4: in-tunnel resolution and exit
  identity.**
  - `observe.resolver: dns://<h>:<p> | tor-socks://<h>:<p>`. Proxy-mode gates
    resolve each destination through the tunnel's own resolver *before*
    connecting (cached by TTL, with a 15 s backoff when down), so flows carry
    `dest.ip` with `resolution: in-tunnel`, and M3 `ip` rules apply to hostnames.
    A name that resolves to a non-public address is refused (`builtin:ssrf-guard`),
    which closes the M2 rebinding gap at the gate.
  - Fail closed: resolver down means `unavailable`, traffic unaffected, and
    `status.json` `resolver.healthy: false`. `tcp`-mode flows are now
    `resolution: "disabled"` (configured endpoints are never resolved), instead
    of `unavailable`.
  - `observe.exit_identity: via-proxy` (opt-in) polls an IP-echo URL
    (default am.i.mullvad.net/json) *through* the chain every 5 min and writes
    `net/exit.ndjson` on change. `glove net status` shows the exit and the
    resolver.
  - **Design change from the plan, measured first:** current gluetun serves DNS
    on all interfaces and its firewall already admits the egress subnet, so no
    `netdns` sidecar sharing gluetun's namespace is needed. gluetun's control
    API needs a credential (401), so exit identity goes via the chain instead.
  - **Verified on live glove-pi-search** (vpn). `web_fetch` destinations got
    in-tunnel IPs, and `exit.ndjson` recorded the VPN exit. A packet sniffer in
    the gate's netns showed destination names sent only to gluetun's resolver,
    with Docker's host-bound DNS asked only for `egress-proxy`/`gluetun`. With
    the resolver dead: `unavailable`, the fetch still succeeded, and again no
    host-bound destination query. Tor `RESOLVE` was verified against the stack's
    `tor` container. The fixture gains in-tunnel IPs and `exit.ndjson`.

- **Network observability, milestone M3: policy.** A `rules.json` control
  channel (`~/.glove/control/<env>/<session>/`, mounted read-only into the gate
  containers only) with a strict, whole-file validator
  (`glove/netgate/policy.py`) shared by the gate and the CLI. Rules are evaluated
  first-match after the built-in guard (then `default`), reloaded about once a
  second without a restart, and applied to new connections. `terminate: true`
  also cuts established flows. A rejected file keeps the last known-good set and
  reports `status.json` `rules.ok: false` with the error. In `tcp` mode a host
  rule can match the TLS SNI, and blocks before any byte is forwarded. New
  commands: `glove net block|unblock|rules`. The CLI never writes, or edits, a
  file the gate would reject. The render refuses any harness mount overlapping
  the control dir. **Verified on live glove-pi-search**: a blocked host's
  `web_fetch` failed and was recorded as `verdict: block` with the rule id; a
  malformed write was rejected while the old rule kept blocking; removing the
  file restored access live.

- **Network observability, milestone M2: proxy awareness, SSRF guard, SNI**
  (`docs/planning/network-observability.md` §2.5.1, §2.7).
  - New `observe: {mode: http-proxy, route: vpn|tor|direct}` per service. The
    gate speaks HTTP `CONNECT` and absolute-form requests, records the real
    destination host and port (`proto: http-connect|http`), and chains to the
    upstream (`chain:http://<to>` by default) by hostname, so the destination is
    only ever passed upstream as text and never resolved by the gate. Requests
    are re-serialised canonically, and absolute-form ones are forced to
    `Connection: close`.
  - `route` is required for `chain:` upstreams. glove cannot verify a tunnel, so
    the operator declares it. Scope is classified per flow: refused or unparsed
    requests are `local`, otherwise `tunnelled` for vpn/tor and `direct` for
    `direct`. `status.json` `upstream.kind` reports the declared route, and
    `direct` is never masked.
  - SSRF guard: non-global IP literals (including IPv4-mapped IPv6 and legacy
    numeric forms), single-label container names and local suffixes are refused
    with a 403 before anything reaches the upstream. They are recorded as
    `verdict: block` with `rule: builtin:ssrf-guard`; unparseable requests get
    `builtin:malformed-request` and a 400. The DNS-rebinding gap is documented
    in `docs/SECURITY.md`.
  - `tcp` mode peeks (never terminates) a TLS ClientHello for its SNI, including
    ClientHellos split across segments, without delaying server-first protocols.
  - Sample `net/` fixture for Layman in `tests/fixtures/netobs/`, generated by
    the real gate code and validated against the handoff schema. The handoff
    brief documents M1–M2 semantics and a table of UI states, ready for a
    design review before the Layman plan.
  - **Verified live** (`tests/integration/test_netgate_m2.sh`, 23/23, on Docker
    Desktop). A CONNECT/TLS fetch through a stub gluetun-style upstream recorded
    `www.origin.test:443`, `web_fetch`, `tunnelled`, with bytes equal to the
    client's raw socket counts (`bytes.down` +1.25% over the body). All 7 SSRF
    probes were refused, and the upstream saw none of them. A DNS sniffer in the
    gate's netns saw only `egress-proxy` queried, never the destination. The M1
    suite still passes (30/30).
  - **Verified on live glove-pi-search** (vpn profile; the pi-search changes are
    on that repo's `network-observability` branch). Pi's real `web_fetch` of
    RFC 9110 recorded `www.rfc-editor.org:443`, `web_fetch`,
    `tunnelled`/`vpn`, with `bytes.down` +4.2% over the response measured
    through the same proxy. `web_search` and the LLM showed as `local` tcp
    flows. The agent's `web_fetch` of `gluetun:8000`, `169.254.169.254` and
    `127.0.0.1:8000` was refused at the gate and never reached gluetun. That
    closes a real path: gluetun's proxy does forward to its own control server,
    whose auth was the only barrier. A DNS sniffer on the proxy gate saw only
    `egress-proxy` queried. **Untested:** podman.
  - `observe.enabled` is now a master switch: with it off, per-service
    `observe:` annotations are inert rather than an error, so a config can carry
    them and toggle observation with one key.

- **Network observability, milestone M1: the netgate as a drop-in socat
  replacement** (`docs/planning/network-observability.md` §8). With
  `observe: {enabled: true}`, each service forwarder runs the new stdlib-only
  netgate (`glove/netgate/`, image `glove/netgate:0.1.0-<src-hash>` from
  `glove/templates/netgate.Dockerfile`) in `forward` mode, with the same
  container name, networks and port as the socat sidecar it replaces. Each
  connection produces flow records: `open`, ~1 Hz `update`s while bytes move, and
  `close` with a `close_reason` of `eof`, `reset`, `timeout`,
  `upstream_unreachable` or `gate_shutdown`. Byte counts are cumulative, and
  records carry timing, tool label and scope in the normative handoff §2 schema.
  They reach a collector, `glove-<session>-netgate`, over a Unix datagram socket
  on a tmpfs volume. The collector runs with `network_mode: none`, is the only
  writer of `net/flows.ndjson` (size-rotated to `flows-<ts>.ndjson`, keep-N,
  0600), and writes `net/status.json`. glove writes `net/session.json` at render
  time with the declared services (including unobserved ones), tool labels,
  upstreams and record mode. New commands: `glove net status` and
  `glove net flows [--follow] [--json] [--tail N]`. The follow mode is a
  reference reader for Layman: it handles rotation by inode and keys on `id`.
  Per-service `observe:` sets `tool`/`scope` or opts out with `false`.
  `record: full`, `http-proxy`/`socks5` modes, and `chain:` upstreams are
  rejected with the milestone that adds them.
  - **Design change from the plan:** instead of one `glove-<session>-netgate`
    container holding every listener, each observed service keeps its own gate
    container and a separate collector does the writing. glove-pi-search's `llm`
    and `search` both listen on `:8080`, which one container can't bind twice.
    The single writer is also what makes the rotation contract hold.
  - **Invariants, each with tests** (`tests/test_netgate_invariants.py`): the
    gate exposes no API on any network; gates are non-root, `cap_drop ALL`,
    `no-new-privileges`, read-only, with no `NET_ADMIN`, no harness
    network/PID namespace, and no harness-home mount; `net/` is a sibling of
    `home/`, and any harness mount that overlaps it (home, `/work`, an add-dir,
    a relocated `config_home_source`) is refused at render with no waiver. Name
    resolution in the gate is limited, by an AST allow-list, to the configured
    upstream and glove's own ingress alias. Host-side code never opens a socket,
    and a monkeypatched resolver proves render and `glove net` never resolve. A
    missing, stopped or unwritable collector drops records (and logs it), never
    traffic. Flow and status shapes are checked against the jsonc in the
    handoff brief itself.
  - **Verified live on Docker 29.8 / Docker Desktop (arm64)** with
    `tests/integration/test_netgate_m1.sh` (30/30). The real Pi harness under
    nono reaches a stub LLM through the gate. `flows.ndjson` records the LLM
    flow with byte counts equal to what a raw client sent and received (1059 up,
    5,000,157 down). The same requests through plain socat return byte-identical
    payloads. Invariants were read back from `docker inspect` and `/proc`, and
    fail-open, rotation, `--follow` across rotations and SIGTERM →
    `gate_shutdown` were all exercised. **Untested:** podman, and a live
    glove-pi-search session (needs its `.env`, Keychain LLM key and VPN
    credentials); its config renders and passes `docker compose config` in
    `tests/test_observe.py`.

- **Resume a prior session** with `glove <harness> … --resume` (`-r`,
  continue-last) or `--session <id>` (a specific full/partial UUID or transcript
  path). A session's transcript lives in the persistent per-session home, not the
  ephemeral container, so resume only appends the harness's own resume flag
  (`pi --continue`/`--session`, `vibe --continue`/`--resume`, `claude-code --continue`/`--resume`
  — modeled declaratively on `HarnessProfile.resume_args`) *inside* the ring-1
  wrapper. The sandbox is re-rendered from the current config every run, so
  **editing config or passing flags before resuming changes the grants** for the
  resumed conversation (e.g. widen `net`, then resume). When a resume run grants
  broader access than the **original** session (`net`, `add_dirs`, `plugins`,
  `allow_root`, `allow_sensitive`, `services`), glove prints a prominent warning —
  prior conversation context runs with the new reach. The comparison baseline is
  a `glove.baseline.yaml` snapshot written once at session creation and never
  overwritten, so it reflects the true original grants, not a drifting previous
  run (a narrow→wide→narrow sequence never mis-warns). `--session` accepts a
  full/partial UUID *or* a transcript path and resolves it to that transcript's
  canonical id before handing it to the harness; `--resume` (continue-last)
  defers to the harness's own project-scoped choice. Transcript discovery is
  per-harness (`sessions/` for Pi/Vibe, `projects/` for Claude Code) via
  `HarnessProfile.sessions_subdir`. Pre-flight validation gives a clear
  glove-level error (with available ids) instead of the harness silently starting
  fresh; missing-transcript and unknown-id cases don't crash. New
  `glove/sessions.py` discovery helpers; transient `resume`/`session_id` never
  persist into `Config`/`glove.effective.yaml`. Tests in `tests/test_resume.py`
  and `tests/test_cli.py`. (Pi verified via dry-run render; vibe/claude-code
  mappings wired but not end-to-end tested.)

### Added

- **`registry.json` records each env's resolved harness home.** Every entry now
  carries a `home` field — the absolute realpath of the harness home resolved at
  `glove run` time (the per-session `envs/<env-id>/sessions/<session>/home` by
  default, or the `config_home_source` override). It is the single canonical
  pointer a passive external monitor (e.g. Layman) uses to find an env's
  transcript logs, so a `run` that renders records it for the registered env,
  including the default layout. Path only — no config contents or secrets.
  Back-compat: an env registered before this change has `home: null` until its
  next `run`. Registry read-modify-writes are serialized with a file
  lock so overlapping `run`/`init` invocations can't clobber each other's home
  updates, a re-bind (e.g. a second `init --name`) carries the recorded home
  forward instead of nulling it, and `load_registry` drops unknown keys / skips
  malformed rows so a future schema field from another glove build can't crash
  readers of the shared `registry.json`.

### Fixes

- **Network observation now starts under Podman.** Found by the follow-up's
  Podman runs; both bugs predate it:
  - the gate's events tmpfs is owned `uid=0,gid=0` under rootless Podman
    (namespace root is the user). `uid=<host uid>` named a subuid, so the
    collector could not create its socket;
  - on SELinux-enforcing hosts, the gate's `net/`/`control/` binds carry
    `selinux: z`, and the tmpfs gets a `container_file_t` context (only when
    `podman info` reports SELinux).
  Verified on rootless and rootful Podman 6.1.2 (Fedora 44, enforcing) and from
  macOS via `podman compose`.
- Rotated `flows-`/`exit-` files are ordered by `(stamp, n)`, not by name: the
  same-millisecond collision name `…Z-1.ndjson` sorted before the older
  `…Z.ndjson`, so pruning could delete the newer file. Rotation also never
  reuses a pruned name now (it could, and the next prune deleted the file just
  rotated), and stays ordered if the clock steps back. `glove net flows` had
  the same ordering bug.
- A size rotation of `exit.ndjson` now carries the current exit into the fresh
  file (it did only on retention), so its latest line is always the present
  origin.
- The collector drains its whole socket queue at shutdown (it stopped at 256
  datagrams).
- JSON state files are written through a per-process temp name
  (`rules.json.<pid>.tmp`), so the CLI and Layman can't clobber each other's
  half-written `rules.json`.

- **netgate: an upstream connect timeout no longer crashes the handler.** The
  `TimeoutError` branch in `Forwarder._connect` fell through to an unbound
  `conn`, so the flow raised `UnboundLocalError` instead of closing with
  `close_reason: timeout` (and an http-proxy client never got its 502).
- **A `harness: false` service named `search` no longer implies the search
  plugin.** The legacy bridge now looks only at harness-facing services, via
  the new `Config.harness_services`.
- **Network observability review fixes.**
  - The in-tunnel resolver now fails open when Tor's SOCKS port (or a DNS TCP
    peer) accepts and then hangs up. The resulting `IncompleteReadError` is an
    `EOFError`, not an `OSError`, so it escaped `InTunnel.resolve` and failed
    the whole proxied connection with no backoff. It now counts as a resolver
    failure: the flow is recorded `unavailable` and traffic is unaffected.
  - A flow cut mid-relay (a `terminate: true` rule, the gate stopping, or a
    reset during the proxy handshake) now closes its upstream socket right away.
    Before, only the client side was closed, and the upstream socket stayed open
    until the garbage collector reclaimed it.
  - `glove net flows -f` no longer drops a record written just before a
    rotation; the old file is read one last time before it is closed.
  - `glove net rules` no longer crashes on a valid `rules.json` that omits the
    optional `default` or `rules` keys.

- **A forced `--env X --config Y` one-off is now registered, so its home is
  recorded.** `glove <harness> --env X --config Y` (no prior `glove init` — the
  pattern the pi launcher scripts use) resolved the env-id but never wrote it to
  `registry.json`, so the subsequent `record_home` found no row to update and the
  session's resolved home was never recorded. A passive external monitor (Layman)
  that reads the registry to locate an env's transcripts therefore never saw the
  session — it stayed invisible no matter how the monitor was configured.
  `run` now registers a *genuinely new* forced env — one whose env-id is absent
  from the registry, run from a cwd not already bound for this harness — binding
  it to cwd exactly as the `--config` cwd branch already does, so `record_home`
  then persists its home. Registration is deferred until after config resolution
  (`_register_forced_env`, called from `run`) rather than done in
  `_resolve_run_env`: the harness needed to bind `(dir, harness)` can be supplied
  by `--config`, so `glove run --env X --config Y` with no positional harness now
  registers too — the earlier `_resolve_run_env` version, gated on the CLI harness
  argument, silently skipped that form. Because it runs inside `run`'s render
  handler and only after a successful render, a forced-env-id clash surfaces as a
  clean `RegistryError` message instead of a traceback, and an aborted run leaves
  no phantom registry row. The guard is deliberately narrow to preserve `--env`'s
  "select an existing env, ignoring cwd" semantics: an already-registered env-id
  is returned untouched and a cwd bound to a different env-id is never rebound.
  Regression tests:
  `tests/test_cli.py::test_forced_env_with_config_registers_and_records_home`,
  `::test_forced_env_registers_when_harness_comes_from_config`,
  `::test_forced_env_selecting_existing_env_is_not_rebound`.

- **`--name`d sessions can reach the LLM again.** The Pi/Vibe harness `baseUrl`
  was built from the bare env-id, but a named session's forwarder sidecar is
  `glove-<env>-<name>-llm`, so the harness dialed a nonexistent host and every
  turn failed with "Connection error" (the network path itself was fine).
  `render_home` now receives the resolved session token, matching the sidecar.
  The harness home is now **per-session** (`sessions/<session>/home/`) rather
  than shared at the env level: it embeds this session-scoped `baseUrl`, so two
  sessions of one env coexisting would otherwise clobber each other's
  `config.toml`/`models.json` and repoint one at the wrong sidecar. Re-running
  the same session reuses its home, so per-session history still persists.
  A power-user `config_home_source` override is still honored as-is. Regression
  tests: `tests/test_cli.py::test_named_session_llm_base_matches_sidecar`,
  `::test_coexisting_sessions_get_isolated_homes`.
- **Plugin build contexts no longer collide.** Each plugin's `copy` sources are
  staged under a plugin-namespaced path (`<plugin>/<name>`) instead of their bare
  basename, so two plugins shipping a same-named source — e.g. the `search` and
  `browser` plugins both ship a `pi-extension/` directory — compose cleanly
  together on Pi instead of overwriting each other in the shared build context.
- **`fd` restored to the Pi base.** It's a core tool Pi shells out to (and tries
  to download at startup, which `PI_OFFLINE=1` blocks in the sandbox), so it's
  baked into the base image rather than dropped with the media toolchain.
- **No redundant derived image** for a plugin that contributes only runtime
  wiring on a harness (e.g. `browser` on Vibe adds an MCP server but no image
  layer): `effective_image` now hashes only layer-contributing plugins, so such
  a session runs the base image directly instead of building a byte-identical
  derived tag.
- **`discover_chrome()` is process-cached**, so repeated plan/doctor calls reuse
  a single filesystem scan.
- **`glove doctor --env`** normalizes a comma-string `plugins:` value to a list
  before the `browser` membership test, matching how config parses it.
- **Pi enforcer wraps commands in a non-login shell** (`bash -c`, not `bash -lc`).
  A login shell sources `/etc/profile`, which nono's default profile denies
  (`deny_shell_configs`), printing a harmless but noisy
  `bash: /etc/profile: Permission denied` on every command. PATH is already set by
  the image env, so login-shell setup was unnecessary.

### Internal

- **Network observability cleanup.**
  - Value sets (scopes, modes, routes, clients, resolve/record modes) and the
    rotation defaults are defined once in `glove.netgate` and shared by the
    host-side validator, the gate's argparse and the rules validator.
  - `glove net status|flows` stream records line by line (`netview.iter_records`)
    instead of loading every rotated file into memory; `--tail N` keeps a
    bounded window. Exit records use the same reader.
  - Gate facts are derived once on `NetworkPlan` (`observe`, `gated`,
    `exit_gate`); `parse_observe` runs once per plan.
  - The in-tunnel resolver shares one lookup across parallel flows to the same
    host, and fails open on any lookup error rather than a growing list of types.
  - Rule matching normalises the flow's host and IP once per evaluation, not per
    rule; the exit poller builds its TLS context once.
  - `netrules.load` fills the optional `default`/`rules` keys, so the CLI no
    longer re-applies the gate's defaults; shared `read_json_dict`,
    `_net_session` and `--env/--session` options replace per-command copies.
  - Dead code removed (`dest_ip_and_resolution`, `Collector.received`, stale
    "rules land in M3" hint in `glove net status`).

- **Back-compat shim de-duplicated.** The rule mapping a legacy config to an
  implied plugin (a `search` service ⇒ `search`; a top-level `browser:` block ⇒
  `browser`) lives in one `_legacy_bridges` helper, consumed by both the plugin
  injection and the deprecation warnings so they can't drift.
- **One comma-list parser.** `config.split_csv` replaces the six hand-inlined
  copies of the `net`/`plugins`/`--with` comma-split across config, CLI, and
  doctor.

### Phase 6 — doctor / policy show integration + migration

- **`glove policy show`** now prints a per-plugin section: each enabled plugin's
  summary, its egress (only via the named forwarder sidecars; shell tools stay
  `--block-net`), its Pi extensions, and its image layer — plus the host services
  the plugins add. The composed harness command shows all loaded `-e` extensions.
- **`glove doctor`** probes the browser provider only when the browser plugin
  (or a legacy `browser:` block) is enabled for the env, reading the provider
  from `plugin_options.browser`.
- **Back-compat shim with deprecation warnings.** A legacy top-level `browser:`
  block still implies the `browser` plugin, and a declared `search` service still
  implies the `search` plugin — both now print a `deprecation:` warning on `run`
  pointing at the `plugins:` form.
- **Example configs migrated** to `plugins:` + `plugin_options:`
  (`vibe-local` → `plugins: [browser]`; `pi-remote-llm` → `plugins: [browser]`
  with `provider: none` for its hand-wired browser; `pi-local` documents
  `plugins: []`).

### Phase 5 — `browser` plugin

- **`browser` plugin** (`plugins: [browser]` / `--with browser` / `--browser`) —
  drive a real host Chromium via Playwright, restored as an opt-in capability.
  The whole browser subsystem is now self-contained under `glove/plugins/browser/`:
  the provider layer (`registry.py`, `base.py`, `host_mcp.py`, `host_server.py`,
  `chrome.py`, moved from `glove/browsers/`), the Pi MCP-client extension
  (`pi-extension/`), and the manifest.
- **Central enablement:** `build_session_plan` now expands browser wiring
  (`_apply_plugin_config`) — host services (Chrome + Playwright), the `browser`
  forwarder sidecar, and harness env — so run, dry-run, `policy show`, and tests
  all compose the same session (previously only the CLI ran `apply_browser`). A
  legacy top-level `browser:` block implies the `browser` plugin; canonical
  options live in `plugin_options.browser`; provider defaults to `host-mcp`.
- Pi loads the browser extension (`-e`); Vibe reaches the same Playwright MCP via
  the plugin's `vibe_mcp` entry (no image contribution needed — native MCP
  client). `_mcp_servers` no longer hardcodes browser; it dispatches to plugins.
- Verified on rootless podman: `browser` composes for Pi (extension +
  `@modelcontextprotocol/sdk`; loads under `nono`, exit 0) and is a no-op image
  layer for Vibe; the extension is absent from the base.

### Phase 4 — `search` plugin

- **`search` plugin** (`plugins: [search]` / `--with search`) — web search via a
  private SearXNG instance, restored as an opt-in capability. Its sources now
  live self-contained under `glove/plugins/search/` (moved out of the harness
  image trees): the Pi extension (`pi-extension/`, loaded via `-e`) and the Vibe
  stdio MCP server (`searxng_mcp.py`).
- **Plugin manifest gains runtime-wiring fields:** `pi_extensions` (Pi `-e`
  paths), `requires_services` (forwarder services the operator must declare —
  glove now errors early if missing), `env_from_services` (endpoint env like
  `SEARXNG_URL` from the `search` sidecar), and `vibe_mcp` (Vibe MCP server
  entries). `build_session_plan` augments the Pi entry, injects the env, and
  validates required services; `harnessconfig._mcp_servers` dispatches to enabled
  plugins instead of hardcoding searxng.
- The `search` wiring is now gated on the **plugin** being enabled, not merely a
  `search` service being present (which previously produced a broken MCP entry
  pointing at removed code). Native Vibe `web_search`/`web_fetch` stay blocked by
  the ring-1 hook; the SearXNG MCP is the search path (unchanged).
- Verified on rootless podman: `search` composes for both harnesses — Pi carries
  the extension + its `typebox` npm dep and loads it under `nono` (exit 0); Vibe
  carries `searxng_mcp.py` with `import mcp` working; both absent from the base.

### Phase 3 — `media` plugin

- **First shipped plugin: `media`** (`plugins: [media]` / `--with media`) —
  restores the image/audio/video analysis toolchain that phase 1 removed, now as
  an opt-in derived layer: `ffmpeg`, `imagemagick`, `webp`, `libimage-exiftool-perl`
  (shared), Pillow via `uv` on Vibe, `python3`+`python3-pil` on Pi. Pure image
  contribution — the tools run as shell commands under the existing ring-1 tool
  policy, so no network/host-service/mount/ring-1 grant is needed.
- Verified on rootless podman: `media` composes for both Vibe and Pi — ffmpeg /
  imagemagick / exiftool / cwebp and `import PIL` all present in the derived
  image, and **absent from the untouched base**. (`fd` is not restored; add it
  per-session with `apt_packages: [fd-find]` if wanted.)

### Phase 2 — plugin interface + image plumbing

- **New `glove.plugins` package** — a `Plugin` manifest (capability-centric, with
  a per-harness `ImageLayer` map) + registry (`register`/`get_plugin`/
  `resolve_plugins`). Empty for now; capabilities are ported in later phases.
- **New config surface:** `plugins: [ … ]` (default `[]`, mirrors `net`) and
  `plugin_options: { <name>: { … } }`; CLI `--with a,b` on `run`/`build`
  (replaces the config list). Unknown plugin names fail loudly. Shown in
  `--dry-run` and `glove policy show`.
- **Derived-layer image composition.** The minimal base stays built from the
  harness Dockerfile; enabling plugins composes a *derived* image
  (`FROM <base>` + one layer set per plugin), tagged with a hash of the enabled
  set (+ apt/pip). No plugins ⇒ the base *is* the session image (byte-identical
  to before). `effective_image` folds the plugin set into the tag.
- Added `HarnessProfile.pip_install` (Vibe → `uv pip install --system`; Node
  harnesses have none) so plugin `pip` layers render per harness.
- Verified on rootless podman: a probe plugin composes `FROM glove/vibe:0.4.0`
  reusing the cached base, tags `glove/vibe:0.4.0-<hash>`, the tool is present in
  the derived image and **absent from the untouched base**, and a second build
  short-circuits on the cached tag.

### Phase 1 — strip the base images

- **The base harness images are now minimal: harness + ring-1 enforcer only.**
  Removed the unconditionally-baked media/analysis toolchain
  (`ffmpeg`, `imagemagick`, `webp`, `libimage-exiftool-perl`, `python3-pil` /
  `Pillow`), the `fd` convenience (Pi), and the SearXNG client
  (`searxng_mcp.py` + `mcp<2` in Vibe; the `searxng` and `browser` Pi
  extensions). Pi now loads only its always-on `enforcer` extension
  (`pi -e …/enforcer`); the `searxng`/`browser` extensions are no longer copied
  into the image.
- **Image tags bumped `0.3.0` → `0.4.0`** (Pi and Vibe) so the new minimal base
  is a distinct tag and existing fat `0.3.0` images aren't silently reused.
- **Sizes (rootless podman, verified):** Vibe **1.09 GB → 685 MB** (−37%);
  Pi **963 MB**. Ring-1 enforcement verified intact — both harnesses exec under
  `nono run` with the rendered harness profile (Pi `pi --version` → 0.85.1;
  Vibe `vibe --version` → 2.25.4 under a profile granting `runtime_paths`).
- **Transitional status:** the plugin system does not exist yet, so capabilities
  that depended on baked code are temporarily unavailable pending their ports —
  **Pi** web-search + browser (extensions removed) and **Vibe** SearXNG search
  (client removed). **Vibe browser via `host-mcp` still works** (it uses Vibe's
  native MCP client + host-side Playwright, nothing baked). No shipped example
  config uses search; `vibe-local` (browser) is unaffected.

## [0.2.0] — unreleased

All six implementation phases are complete.

### Changes

- **Robustness follow-ups after the PR review (five fixes).**
  - *`_host_info` no longer sticks on a transient failure.* The `@functools.cache`
    on `_host_info` permanently memoized `{}` if the very first `podman info` probe
    of a process failed (e.g. the machine not yet ready), silently degrading
    rootless/seccomp/kernel for the whole run. It now caches only *successful*
    probes (module-level dict + `_host_info.cache_clear`), so the next call
    re-probes once podman is up; the module-scope caching that avoids re-probing
    across fresh `get_runtime('podman')` instances is preserved.
  - *`podman info` parsing hardened against a `|` in the kernel string.* The
    probe format put the free-text kernel field first and split on `|`; a kernel
    description containing a pipe shifted rootless/seccomp onto a fragment. The
    two boolean flags now come first and the kernel last, split with `maxsplit=2`.
  - *`Runtime.unsupported_enforcer_reason` is now on the Protocol.* The doctor
    compatibility gate relied on a `getattr(..., lambda _e: None)` fallback, so a
    runtime that forgot the method silently skipped the gate. It is declared on
    the `Runtime` Protocol (a type error if omitted), the stub runtimes implement
    it, and doctor calls it directly.
  - *Render-time seccomp refusal now honours `--i-know-what-i-am-doing seccomp`.*
    `render()` hard-failed on the built-in-default gap even when the operator had
    waived the seccomp row (which `validate_hardening` accepts), making the
    override silently ineffective. The refusal now also checks `overrides`, so the
    two paths agree.
  - *Tool-profile read-surface tradeoff documented honestly.* The shell-tool nono
    profile reads whole `runtime_paths` trees (needed to exec node/python); the
    "exposes no secret" comment overstated the guarantee. It now describes the
    defense-in-depth tradeoff explicitly — an image-layout assumption bounded by
    `network.block` (no exfil) and `environment.deny_vars` (secret-var stripping).

- **Hardening follow-ups after the podman review (five fixes).**
  - *Interpreter paths now readable to shell tools too.* The `nono run` exit-127
    fix (interpreter/runtime paths in the read set) had been applied only to the
    *harness* profile. A shell **tool** command that execs an interpreter outside
    nono's default system reads (node/npm under `/usr/local`, a uv/venv python
    under `/opt/uv`) hit the same Landlock exec denial and died exit 127. Both
    profiles now share one read set (`_read_paths`) that includes
    `profile.runtime_paths` — read-only, so `tool.json` still can't read the
    harness config home or any secret.
  - *Seccomp invariant coupled to what actually renders.* `validate_hardening`
    only checks that the *plan* names a profile; on podman that value is discarded
    (no `seccomp=` line is emitted). `render()` now refuses unless the runtime
    declares `RuntimeCaps.applies_builtin_seccomp` — so a runtime that drops
    glove's profile without a validated built-in default can no longer render an
    unpinned container silently. podman sets the flag (built-in moby-derived
    default); docker must emit the vendored profile.
  - *podman + srt incompatibility is now a first-class doctor gate.* The refusal
    lived only inside the compose render hook, so `glove doctor --runtime podman
    --enforcer srt` reported OK and `glove run` aborted late. A single
    `Runtime.unsupported_enforcer_reason()` now backs both the render refusal and
    a `fail` check surfaced by `glove doctor` up front.
  - *`podman info` probed once, cached process-wide.* doctor called `podman info`
    three times per run (kernel, security fields, rootless) and the rootless cache
    lived on an instance that `get_runtime()` rebuilds each call. A module-level
    memoized `_host_info(cli)` templates all three fields in one call and survives
    across the doctor/plan/run flow (verified: 1 call across 3 fresh instances).
    (A later follow-up narrowed the memoization to successful probes only.)
  - *host-gateway forwarders on podman verified, not just assumed.* On rootless
    podman 6 `host.docker.internal:host-gateway` resolves to gvproxy's host
    address (192.168.127.254) — identical to podman's built-in
    `host.containers.internal`, distinct from the netavark bridge gateway — so it
    reaches the host without shadowing it. Documented in `runtimes/podman.py`.

- **Fixed: the harness TUI could not launch under nono (`nono run` exited 127).**
  The ring-1 *harness* profile granted `/etc/glove`, `/opt/glove`, and the ro
  mounts, but **not the harness's own interpreter/runtime** — vibe's shebang
  resolves to a python under `/opt/uv`→`/usr/local`, and pi/node lives under
  `/usr/local`. Under Landlock those paths were unreadable, so the kernel could
  not exec the TUI and the container died with exit 127 and no output (this is
  the live-TUI path, previously exercised only manually). `HarnessProfile` now
  declares `runtime_paths` (default `/usr/local`; vibe adds `/opt/uv`) which the
  nono renderer adds to `harness.json`'s read list — tool commands (`tool.json`)
  are unaffected, so a shell still can't read the config home. Verified: the Vibe
  TUI now renders under `nono run` (podman, `compose run`): "Mistral Vibe v2.25.0
  · glove · 3 models · 1 hook".
- **Podman runtime validated on rootless podman (macOS/libkrun) and promoted
  from "untested" to a first-class backend.** `RuntimeCaps.tested` is now `True`
  for podman. Rendering diverges from docker in two podman-specific ways, both
  handled automatically: (1) rootless podman maps the invoking uid to container
  root, so a `user: <uid:gid>` harness cannot write host-owned bind mounts —
  glove now emits `userns_mode: keep-id` on rootless podman so ownership passes
  through; (2) `podman compose` runs an external compose provider (docker-compose)
  that *inlines* a referenced seccomp profile's JSON, which podman's compat API
  rejects ("file name too long") — glove omits the custom profile on podman and
  relies on podman's built-in default (the same moby-derived filter that already
  allows `landlock_*`). `glove doctor --runtime podman` uses podman's version/info
  fields (`.Server.OsArch`, `.Host.Kernel`, `.Host.Security.*`), reports whether a
  compose provider is installed, and drops the docker-only File-sharing hint.
  Verified end-to-end: `podman compose config` parses the rendered project; the
  hardened harness comes up with `cap_drop=ALL`/CapEff=0, no-new-privileges,
  read-only rootfs, pids/mem limits, and an internal-only network; all six ring-1
  nono checks pass (write /work, config dir denied to shell, network blocked,
  secret stripped, hook rewrite, web_fetch deny) against the real
  `glove/vibe:0.3.0` image (Landlock ABI 9 in the libkrun VM); and the `llm`
  forwarder sidecar reaches a Tailscale-hosted LLM through gvproxy egress.
  `srt` on podman is not supported yet (its relaxed profile can't be inlined) and
  fails fast with a clear message. Needs a compose provider (`brew install
  docker-compose`).

- **glove no longer writes anything into the project working tree**: browser
  output (`{media_dir}`, e.g. Playwright screenshots) defaulted to
  `<workdir>/research/<collection>/media` and glove `mkdir`'d it on launch,
  littering whatever repo you ran in with a `research/` tree. Output now lives in
  glove's own session state (`~/.glove/envs/<env>/sessions/<session>/media`); the
  agent gets screenshots inline from the browser tool. The research-specific
  `collection` config field and the `research_dir`/`filtered_dir`/`collection`
  command placeholders are removed, and the agent context file no longer tells the
  agent to "write deliverables under /work/research/…". glove is a generic
  sandbox and leaves no files behind in the repo it is launched on.
- **Examples moved to `docs/examples/` and anonymized**: the presets left the repo
  root and were rewritten to be generic (no personal project names, hosts, or
  briefs). `pi-local` (local LLM, no browser), `pi-remote-llm` (remote LLM over
  SSH + dedicated Playwright browser), `vibe-local` (Vibe + browser provider
  block).
- **Browser docs + a remote-LLM example, and clearer host-mcp doctor guidance**:
  the default `host-mcp` browser provider had no doc and `glove doctor` only said
  "Google Chrome not found". Setting up a dedicated Playwright browser meant
  discovering that `@playwright/mcp`'s `--browser` accepts only channels
  (defaulting to a *system* Chrome) and that the fix is `--executable-path` to
  Playwright's Chrome for Testing. Now documented in `docs/pi-remote-llm.md`,
  demonstrated end-to-end in `docs/examples/pi-remote-llm.glove.yaml` (remote LLM over
  SSH tunnel + dedicated headed Playwright Chromium), and `glove doctor
  --browser host-mcp` detects Chrome for Testing and prints the `--executable-path`
  to use (or points to `npx playwright install chromium`).
- **nono state roots now sit on tmpfs, fixing Pi launch on Docker Desktop
  (macOS/Windows)**: nono's supervisor creates a PTY-proxy Unix socket under
  `$HOME/.local/state/nono` and lock/audit state under `$HOME/.nono`, both on the
  `/home/agent` bind mount. On Docker Desktop that mount is a virtiofs/gRPC-FUSE
  share which cannot host an `AF_UNIX` socket (`bind()` → `EINVAL`, os error 22),
  so the sandbox never started. Enforcers can now declare `extra_tmpfs`; nono
  backs those two state roots with tmpfs (native fs, ephemeral per-session, and —
  being outside both Landlock profiles' allow-lists — still off-limits to the
  agent). All tmpfs mounts render as long-form `type: tmpfs` with an explicit
  `mode: 01777`: a bare tmpfs over a mountpoint that already exists on the bind
  mount comes up `755 root:root`, which the non-root harness can't write
  (`EACCES`, os error 13).
- **Pi `harness_config` now overrides generated settings/model fields**: the Pi
  `settings.json` (e.g. `defaultThinkingLevel`) and the per-model entry in
  `models.json` were fully hardcoded, so a session could not raise the default
  thinking level or tune model fields without patching glove. `harness_config`
  may now carry a `settings` mapping (deep-merged, preserving the derived
  `SEARXNG_URL`) and a `model` mapping (overlaid on the model entry), matching
  how the Vibe renderer already honours `harness_config`.

### Fixes (post-review)

- **Environment context file now renders the resolved `MountPlan`**: the
  "How your environment works" block reported container paths by recomputing
  basenames, so it diverged from the real mounts on basename collisions
  (`/mnt/foo` vs `/mnt/foo-2`) and still claimed a `/work` mount when an
  add-dir absorbed the workdir. It now lists the actual mounts/modes and the
  real `working_dir`.
- **Browser provider `context_note` is rendered**: host-mcp's screenshot-dir
  guidance and host-server's exact `ws://…` endpoint reached `BrowserWiring`
  but were dropped from the context file. They are now emitted in the Network
  section.
- **`glove init --name` refuses a name already bound to another
  `(dir, harness)`**: an env-id owns the whole `~/.glove/envs/<env-id>/` tree,
  so a forced name that collides is rejected (`RegistryError`) instead of
  silently pointing two projects at one directory.
- **`glove ps` groups by the compose project label** instead of parsing the
  container name, so `compose run`'s `-run-<hash>` suffix and dashed service
  roles (`my-llm`) are attributed to the right session.
- **`glove doctor` Landlock probe applies glove's vendored default seccomp
  profile**, so it reflects the syscall filter the real harness runs under.
- Removed the dead `SUDO_RELAY` constant (superseded by `SUDO_RELAY_BODY`).

### Tooling

- **`ruff` is now a dev dependency with a project config** (`[tool.ruff]` in
  `pyproject.toml`: E/F/W/I/UP/B/SIM/C4/RUF at line-length 120, Typer's `B008`
  exempted, `tests/integration` + `glove/harnesses` excluded). `uv run ruff check
  glove tests` is clean and is part of the documented test flow. The existing
  code was brought up to the ruleset (import order, unused imports, `Optional[X]`
  → `X | None` in the CLI, minor simplifications).

### Fixes (code review, 2nd pass)

- **The headed-Chrome host helper now discovers the browser binary** instead of
  hardcoding `"/Applications/Google Chrome.app/…"`. Both browser providers
  (`host-mcp`, `host-server`) launch a headed Chrome on the host; on Linux, or on
  a macOS host with only Playwright's Chrome for Testing (the very setup `glove
  doctor` recommends), that path did not exist, so the tmux session died, the
  readiness check timed out on `:9222`, and the Playwright MCP could never attach —
  the browser feature was broken via the provider sugar. `headed_chrome_service()`
  now resolves a system Google Chrome / Chromium, then Chrome for Testing, across
  macOS, Linux and Windows (`chrome_executable()`), and the `host-mcp` doctor check
  reports whichever system browser it found.
- **`glove down <env>` now tears down every session, including `--name`d ones.**
  It only ever ran `docker compose -p glove-<env> down` and read the default
  session dir, so a session started with `--name feat` (compose project
  `glove-<env>-feat`, host services keyed the same) was orphaned — harness
  container and forwarder/host sidecars left running with no CLI path to stop
  them. `down` now iterates every session under the env (or one, with `--name`),
  tearing down each session's compose project and host services; host services are
  keyed by the session token to match.
- **A declared service without the `service` net profile now errors loudly.** A
  hand-declared service with the default `net: [none]` was silently dropped — no
  sidecar, no error — while the harness config still pointed at the (dead)
  endpoint, so the first turn failed with an opaque connection-refused. glove's
  security default is *no network unless explicitly requested*, so rather than
  silently dropping (the bug) or auto-granting a route (equally wrong), the
  contradiction now raises a clear `ConfigError` telling the operator to add
  `service` to `net`. Browser providers already flip `net` to include `service`,
  so the `--browser` sugar is unaffected.
- **The LLM API key is redacted from the persisted `glove.effective.yaml`.** The
  rendered effective config wrote `llm_api_key` in cleartext under `~/.glove` on
  every run, an extra on-disk copy of the secret never scrubbed on `down`.
  `Config.to_yaml(redact_secrets=True)` nulls it in that artifact; the real key
  still lives only in the (git-ignorable) env source and is injected at render
  time.
- **nono's per-session tmpfs now targets `~/.local/state/nono`, not the whole
  `~/.local/state`.** The broad mount shadowed every sibling's persisted state
  (caches, tokens, resume data) under the `/home/agent` bind mount each session;
  it now isolates only nono's own state root.
- **The browser MCP endpoint has a single construction site.** `BROWSER_MCP_URL`
  was built both in the `host-mcp` provider wiring and again in `plan._service_env`,
  two strings that had to stay byte-identical by hand. The provider now only
  declares the `browser` service; the endpoint is derived once, at plan time, from
  that service (also covering hand-wired configs).

### Phase 6 — runtime stubs, podman, docs

- **`glove doctor` surfaces runtime status independently of container probes**:
  `podman` is flagged **UNTESTED** and the `apple-container`/`gondolin`/`utm`
  stubs are flagged **not implemented**, even in `--no-container`/host-only mode.
- **Per-backend mapping** worked out for the stub runtimes: podman (rootless
  userns / seccomp / internal-net validation), apple-container (one VM per
  container, no compose → glove orchestrates sidecars, macOS 26 + Apple silicon),
  gondolin (OCI → mapped-TCP egress, no UDP), and utm (Linux VM running the same
  image under Podman over SSH/`utmctl`).
- **`docs/SECURITY.md`** — the threat model: three-ring table, assets ×
  adversaries × rings, the Docker Desktop macOS blast-radius explanation
  (container root = VM root, File-sharing list, config-not-fate), operator
  recommendations (narrow File sharing, ECI, keep Docker Desktop patched — cites
  CVE-2026-2664 / CVE-2026-6406 as examples of the class, prefer per-container
  VMs, prefer nono over srt), and the explicit list of what glove does **not**
  defend against (kernel 0-days, malicious host, side channels, DoS beyond the
  limits, authorized-but-bad edits, supply chain).
- **README** rewritten: three-ring overview, quick start, full `glove.yaml`
  reference, CLI reference, integration-test commands, and links to the new docs.
- New tests: doctor surfaces untested podman + the stub runtimes.

### Phase 5 — browser providers

- **Browser provider layer** (`glove/browsers/`): a `BrowserProvider`
  turns a compact `browser: {provider, port}` block into the concrete wiring —
  forwarder sidecars (network allow-list), host helpers (headed Chrome +
  Playwright MCP/server, run by `hostsvc`), harness env, and an agent-facing
  context note. `apply_browser(cfg, session)` merges it into the session;
  hand-configured `services`/`host_services` win (v1 configs keep working).
- **`host-mcp`** (v2 default): headed Chrome + `@playwright/mcp` via CDP →
  `glove-<session>-browser:<port>` forwarder; `BROWSER_MCP_URL` for Pi's
  extension / Vibe's auto-MCP; `--allowed-hosts` pinned to the sidecar,
  `--output-dir` in the collection media dir.
- **`host-server`**: `playwright run-server` on the host with a **random
  per-session `--ws-path`**; the agent connects with
  `chromium.connect($PLAYWRIGHT_WS_ENDPOINT)`. `doctor` runs a **version-pin
  check** (host Playwright minor must equal the image's); requires the
  playwright package in the harness image.
- **Specs** worked out for the deferred providers: sidecar-desktop
  (Xvfb/x11vnc/noVNC sidecar on the internal net, `127.0.0.1` noVNC only,
  egress-proxy sidecar) and vm-desktop (UTM/`utmctl` + gondolin).
- `glove run --browser …`, `glove doctor --browser …`, and a provider-aware
  context note (host-server tells the agent to use `chromium.connect`).
- New tests (9): provider wiring, `apply_browser` merge/dedup/net-enable,
  ws-path stability, version parse. Suite: **119 passed**.
- **Verified** (host lacks a full Chrome/display + LLM, so live navigation is
  manual): both providers render the correct forwarder sidecar + host services +
  env from the `browser:` block; the **browser security rule holds** — the browser
  endpoint is reachable by the harness (ring-0 net) but `tool.json` is
  `network.block: true`, so a prompt-injected shell `curl` cannot drive it; the
  host-server version-pin check correctly flagged host Playwright 1.62.1 ≠ image
  1.55.0. The visible-Chrome-navigates + screenshot-to-`/work` end-to-end needs a
  live LLM and is documented as manual.

### Phase 4 — srt enforcer (opt-in)

- **`SrtEnforcer`** (`glove/enforcers/srt.py`): renders a single
  `srt-settings.json` (`filesystem.allowWrite` = /work + rw mounts + /tmp,
  `denyRead`/`denyWrite` = the harness home mount, `network.allowedDomains` = []
  → no tool network, `enableWeakerNestedSandbox` per `srt.nested`). Wraps **tool
  commands only** (`srt -s … -- bash -lc <cmd>`) via the shared tool-wrapper
  file; the harness *process* is unwrapped (ring-0 only), documented as a gap.
  No credential injection (key stays in the harness env). Registered in
  `get_enforcer`; `enforcer: srt` selects the surgical `nested-userns` seccomp
  (Phase 1) and, for `srt.nested: strong`, `systempaths=unconfined`.
- **`-srt` image variant**: ARG-gated `bubblewrap`/`socat`/`sandbox-runtime@0.0.75`
  install in the Pi Dockerfile; `glove build pi --enforcer srt` and the plan's
  image resolution append `-srt`.
- **`glove policy show`**: prints the ring-0 hardening (with the
  `systempaths=unconfined` warning), the harness command, the rendered ring-1
  policies, and the enforcer's documented gaps.
- **`glove doctor --enforcer srt`** runs a bwrap smoke test as uid 1000 under the
  relaxed profile in a baked `-srt` image (reproduces weak mode).
- **Finding (verification is real):** srt's `--ro-bind /` does **not** downgrade
  a nested docker bind mount, and denying a *subdir* of a bind mount is a no-op —
  so `allowWrite` alone would leave the harness home writable to tool commands.
  Fixed by denying the whole home **mount point** in `denyRead`/`denyWrite`
  (verified: write to a home subdir is denied, /work still writable). Recorded in
  `SrtEnforcer.gaps`.
- New tests (8: settings weak/strong goldens, unwrapped-harness, `-srt` image,
  relaxed seccomp, gaps). Suite: **110 passed**.
- **Verified against the real `glove/pi:0.3.0-srt` image**
  (`tests/integration/test_pi_srt.sh`, **7/7**): weak mode enforces under the
  surgical seccomp (write /work ok, write outside allowWrite denied, network
  blocked, `denyRead` hides the harness home); strong mode fails without
  `systempaths=unconfined` and succeeds with it (matrix).

### Phase 3 — Vibe integration

- **Vibe image (`glove/vibe:0.3.0`)**: bakes the pinned nono binary, the
  fail-closed entrypoint, and `/opt/glove/vibe-hook`. The harness process is
  nono-wrapped generically (as Pi), so its config home (`/home/agent/.vibe`) is
  writable to the harness but denied to shell tools.
- **`vibe-hook`** (`glove/harnesses/vibe/vibe_hook.py`): a `pre_tool`
  hook that reads Vibe's tool-call JSON on stdin and (a) rewrites the `bash`
  tool's `command` to run under the enforcer's per-command wrapper (from
  `/etc/glove/enforcer/tool-wrapper.json`), returning a full
  `hook_specific_output.tool_input` replacement; (b) denies direct-egress tool
  names (`web_fetch`/`web_search`); (c) passes everything else through. Fails
  closed on bad input/missing wrapper.
- **Seeding** (`harnessconfig`): writes `~/.vibe/hooks.toml` (one `pre_tool`
  hook, `match="*"`, `strict=true`) when an in-container enforcer is active, and
  sets `experimental_bash_tool = false` so the shell-spawning bash tool is used
  (the plan's `managed_shell_tools_enabled` key is outdated).
- New tests (11): the hook's rewrite/deny/passthrough/fail-closed logic (pure
  Python, incl. a stdin end-to-end run) and hooks.toml seeding. Suite:
  **102 passed**.
- **Verified against the real `glove/vibe:0.3.0` image**
  (`tests/integration/test_vibe_nono.sh`, **10/10**): nono enforces in the Vibe
  image (write /work ok, vibe home denied to shell, net blocked, secrets
  stripped); the baked `vibe-hook` rewrites a bash tool call through the wrapper,
  denies `web_fetch`, and exits non-zero (→ strict denial) on bad input;
  entrypoint execs with valid policies. The live-TUI path (hook firing during a
  real `vibe -p` run, strict denial in the UI) is documented as manual.

### Phase 2 — nono enforcer + Pi integration (the core deliverable)

- **Ring-1 enforcer layer** (`glove/enforcers/`): `Enforcer` protocol
  (`base.py`), the default **nono** backend (`nono/` — policy renderer, harness
  wrapping, pinned 0.75.0 binary in `version.py`), and a `none` backend
  (ring-0 only). `get_enforcer()` registry.
- **Two nono policies per session** (`enforcers/nono/policies.py`), both
  extending nono's built-in `default`:
  - `harness.json` — the harness *process*: /work + rw mounts + its config
    subdir + /tmp writable, ro mounts readable, network open (ring 0 already
    limits routable hosts to the sidecars).
  - `tool.json` — every *shell command*: /work + rw mounts + /tmp writable,
    **harness home denied** (omitted → Landlock denies), `network.block`, and
    secret-shaped env vars stripped (`deny_vars`) so a prompt-injected `env`
    cannot read the LLM key.
  Wrapped via `nono run … -- <TUI>` (harness) and `nono wrap … -- bash -lc`
  (tools); nested Landlock only tightens. No `SYS_PTRACE` needed (no proxy).
- **`SessionPlan`/render wiring**: `build_session_plan` now renders policies,
  wraps the harness command, and the docker runtime mounts the policy dir
  read-only at `/etc/glove/enforcer` and merges enforcer env. `glove run`
  writes policies to `sessions/<name>/enforcer/`.
- **Pi image (`glove/pi:0.3.0`)**: bakes the pinned nono binary, a fail-closed
  `/opt/glove/entrypoint.sh` (validates policies before exec), and a
  dependency-free `enforcer` Pi extension that rewrites every `bash` tool call
  and `!` command through the per-command wrapper (via `tool_call` in-place
  mutation + `user_bash` operations).
- **Context generator** (`harnessconfig.build_environment_context`): a
  generated "How your environment works" block (mounts/modes, shell has no
  network, browser tool is the only web path, RUN ON HOST relay, output dir).
- **`glove doctor`** now runs the selected enforcer's checks.
- New tests (golden policy files verified with real `nono profile validate`,
  render/wiring, context block, pin-drift guard). Suite: **91 passed**.
- **Verified against the real `glove/pi:0.3.0` image**
  (`tests/integration/test_pi_nono.sh`, **16/16**): write /work ok; harness
  home denied to shell; network blocked; secrets stripped; /etc write, apt,
  sudo all fail; the 4-part malicious-extension drill all fail; harness writes
  its own config home; a nested tool is denied the harness transcript;
  entrypoint fails closed on an invalid policy. The LLM/TUI-dependent checks
  (trivial prompt, browser_navigate) are documented as manual. Deferred:
  nono proxy allowlist + credential-injection (blocked on HTTPS-upstream for the
  plain-HTTP LLM sidecar).

### Phase 1 — runtime layer + hardening + doctor

- **Ring-0 runtime layer** (`glove/runtimes/`): `Runtime` protocol +
  `RuntimeCaps`/`Check`/`RenderedProject` (`base.py`), full `DockerRuntime`
  (`docker.py`, renders the compose project from a `SessionPlan` and enforces
  hardening), `PodmanRuntime` subclass (ships **untested**), and registered
  `apple-container`/`gondolin`/`utm` stubs. `get_runtime()` registry.
- **`SessionPlan`** (`glove/plan.py`): runtime-agnostic resolution of `Config`
  + mounts + network + hardening; `compose.py` is now a thin shim over it.
- **Hardening set** (`glove/hardening.py`): `Hardening`/`Limits`
  dataclasses and `validate_hardening()` that refuses to render a
  non-compliant project unless a row is waived with
  `--i-know-what-i-am-doing <key>`. Rendered rows now include `ipc: private`,
  `pids_limit`, `mem_limit`, `cpus`, and an explicit seccomp profile path.
  `allow_root` now keeps all hardening except the non-root user (was: relaxed
  everything).
- **Seccomp profiles** (`glove/runtimes/seccomp/`): vendored moby `default.json`
  + a `make_profile.py` that generates the *surgical* `nested-userns.json`
  (only the 14 namespace/mount syscalls bwrap needs; `bpf`/`perf_event_open`/
  `syslog`/… stay gated). A test asserts the surgical diff and that the
  checked-in file is current.
- **Session naming + layout**: `glove run --name SESSION` renders coexisting
  sessions under `envs/<env>/sessions/<name>/`. New `glove ps`.
- **`glove doctor`**: host + runtime + enforcer probes with a
  `--json` mode; runs a hardened container to report Landlock ABI, userns,
  kvm, and effective caps. New config keys: `runtime`, `enforcer`, `limits`,
  `tools`, `browser`, `enforcer_options`.
- New tests (30): hardening rows + refusal, seccomp surgical diff, plan
  resolution, runtime registry/render/ps, doctor shape. Suite: **78 passed**.
- **Verified on Docker Desktop 29.7.2:** `docker compose config` parses the
  rendered project; a started container shows `CapDrop=[ALL]`,
  `no-new-privileges` + seccomp profile, `ReadonlyRootfs`, `PidsLimit=512`,
  `Memory=4g`, `IpcMode=private`, `User=501:20`; inside: `id -u=501`,
  `CapEff=0`, `host.docker.internal` unresolvable, read-only rootfs, Landlock
  ABI 8; `glove doctor` reports Landlock ABI ≥ 4. The llm-sidecar positive-path
  check remains deferred.

### Phase 0 — bootstrap from v1

- Bootstrapped the v2 repository from the v1 working tree (`env-identity`
  branch, uncommitted changes included): `glove/`, `tests/`, `examples/`,
  `pyproject.toml`, `uv.lock`.
- Bumped package version `0.1.0` → `0.2.0`.
- Added `README.md`, `CLAUDE.md` (repo conventions), and this `CHANGELOG.md`.
- v1 test suite passes unchanged under `uv run pytest -q`.
