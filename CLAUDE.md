# Repo conventions for Claude Code

`glove` v2 — a sandbox launcher for agentic coding harnesses. The design
authority is **`docs/PLAN.md`**; the research behind it is in
**`docs/research/`**. Read both before changing behavior. Work the phases in
`docs/PLAN.md` §8 in order; do not start a phase while the previous phase's
verification block is red.

## Toolchain

- Python ≥ 3.11, managed with **uv**. Never call `pip` or a bare `python`.
  - `uv sync` — install/refresh the environment.
  - `uv run pytest -q` — run the test suite (must be green before moving on).
  - `uv run glove …` — run the CLI.
- Re-verify runtime assumptions with `bash docs/research/run-all.sh`. Note:
  `podman`, `nono`, `srt`, and Apple `container` are **not** installed on this
  host — anything needing them runs inside Docker images.

## Security defaults are not negotiable (PLAN §3.2)

Harness containers are always: non-root, `cap_drop: ALL`,
`no-new-privileges`, read-only rootfs, seccomp profile, pids/memory limits,
internal network only. **Never** mount `docker.sock`, add
`host.docker.internal`/host-gateway to the harness, or use `--privileged`.
The default in-container enforcer is **nono** (Landlock); **srt** is opt-in and
needs the *surgical* relaxed seccomp profile from §3.4 (not the coarse research
profile).

## Where things render

- On-disk layout: `~/.glove/` (or `$GLOVE_HOME`) — see PLAN §7.1.
- Ring-1 policies render to
  `~/.glove/envs/<env>/sessions/<name>/enforcer/` and mount **read-only** at
  `/etc/glove/enforcer/` — never inside `/work`, never writable by the agent.

## Working agreements

- **Never `git add`, `git commit`, or `git push` without asking first.**
  Propose a commit message at the end of each phase and wait for approval.
- Verification is real: when a phase calls for running containers, actually run
  them and paste the output. If something can't be verified on this machine,
  say so and mark it "untested" rather than claiming it works.
- Keep `docs/PLAN.md` as the design authority. Put implementation notes in
  `docs/` *next to* it, not inside it, unless a design decision actually
  changed. Track deferred/open items in `docs/TODO.md`.
- Per phase, deliver: code + tests, an updated `README.md` status table, and a
  `CHANGELOG.md` entry.
