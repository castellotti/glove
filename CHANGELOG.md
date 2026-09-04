# Changelog

All notable changes to glove are documented here.

## [0.2.0] — unreleased

All six implementation phases are complete.

### Changes

- **Browser docs + a remote-LLM example, and clearer host-mcp doctor guidance**:
  the default `host-mcp` browser provider had no doc and `glove doctor` only said
  "Google Chrome not found". Setting up a dedicated Playwright browser meant
  discovering that `@playwright/mcp`'s `--browser` accepts only channels
  (defaulting to a *system* Chrome) and that the fix is `--executable-path` to
  Playwright's Chrome for Testing. Now documented in `docs/pi-remote-llm.md`,
  demonstrated end-to-end in `examples/pi-remote-llm.glove.yaml` (remote LLM over
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
