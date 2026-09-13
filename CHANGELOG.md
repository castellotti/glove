# Changelog

All notable changes to glove are documented here.

## [Unreleased] — minimal core + opt-in plugins (in progress)

Reworking glove into a tight, minimal sandbox with every optional capability
behind an off-by-default plugin system (design note:
`docs/planning/minimal-core-plugins-designnote.md`). Landing in phases; the
default (no-plugins) path stays fully working at each step.

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
