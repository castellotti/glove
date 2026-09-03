# Changelog

All notable changes to glove are documented here. This project follows the
phase plan in `docs/PLAN.md`.

## [0.2.0] — unreleased

### Phase 3 — Vibe integration

- **Vibe image (`glove/vibe:0.3.0`)**: bakes the pinned nono binary, the
  fail-closed entrypoint, and `/opt/glove/vibe-hook`. The harness process is
  nono-wrapped generically (as Pi), so its config home (`/home/agent/.vibe`) is
  writable to the harness but denied to shell tools.
- **`vibe-hook`** (`glove/harnesses/vibe/vibe_hook.py`, PLAN §5.3): a `pre_tool`
  hook that reads Vibe's tool-call JSON on stdin and (a) rewrites the `bash`
  tool's `command` to run under the enforcer's per-command wrapper (from
  `/etc/glove/enforcer/tool-wrapper.json`), returning a full
  `hook_specific_output.tool_input` replacement; (b) denies direct-egress tool
  names (`web_fetch`/`web_search`); (c) passes everything else through. Fails
  closed on bad input/missing wrapper.
- **Seeding** (`harnessconfig`): writes `~/.vibe/hooks.toml` (one `pre_tool`
  hook, `match="*"`, `strict=true`) when an in-container enforcer is active, and
  sets `experimental_bash_tool = false` so the shell-spawning bash tool is used
  (the plan's `managed_shell_tools_enabled` key is outdated — see docs/TODO.md).
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
  plain-HTTP LLM sidecar) — see docs/TODO.md.

### Phase 1 — runtime layer + hardening + doctor

- **Ring-0 runtime layer** (`glove/runtimes/`): `Runtime` protocol +
  `RuntimeCaps`/`Check`/`RenderedProject` (`base.py`), full `DockerRuntime`
  (`docker.py`, renders the compose project from a `SessionPlan` and enforces
  hardening), `PodmanRuntime` subclass (ships **untested**), and registered
  `apple-container`/`gondolin`/`utm` stubs. `get_runtime()` registry.
- **`SessionPlan`** (`glove/plan.py`): runtime-agnostic resolution of `Config`
  + mounts + network + hardening; `compose.py` is now a thin shim over it.
- **Hardening set** (`glove/hardening.py`, PLAN §3.2): `Hardening`/`Limits`
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
  sessions under `envs/<env>/sessions/<name>/` (§7.1). New `glove ps`.
- **`glove doctor`** (PLAN §3.3): host + runtime + enforcer probes with a
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
  ABI 8; `glove doctor` reports Landlock ABI ≥ 4. See docs/TODO.md for the
  deferred llm-sidecar positive-path check.

### Phase 0 — bootstrap from v1

- Bootstrapped the v2 repository from the v1 working tree (`env-identity`
  branch, uncommitted changes included): `glove/`, `tests/`, `examples/`,
  `pyproject.toml`, `uv.lock`.
- Moved v1 design docs under `docs/v1/` (`DESIGN.md`, `plan-environments.md`).
- Bumped package version `0.1.0` → `0.2.0`.
- Added `README.md` (points at `docs/PLAN.md`), `CLAUDE.md` (repo conventions),
  and this `CHANGELOG.md`.
- v1 test suite passes unchanged under `uv run pytest -q`.
