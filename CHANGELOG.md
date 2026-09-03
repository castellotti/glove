# Changelog

All notable changes to glove are documented here. This project follows the
phase plan in `docs/PLAN.md`.

## [0.2.0] — unreleased

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
