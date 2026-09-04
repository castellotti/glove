# Repo conventions for Claude Code

`glove` v2 — a sandbox launcher for agentic coding harnesses. It runs a chosen
harness (Pi, Mistral Vibe, later Claude Code) inside a hardened container with an
in-container kernel enforcer wrapping the agent and every command it runs.

## Toolchain

- Python ≥ 3.11, managed with **uv**. Never call `pip` or a bare `python`.
  - `uv sync` — install/refresh the environment.
  - `uv run pytest -q` — run the test suite (must be green before moving on).
  - `uv run glove …` — run the CLI.
- `podman`, `nono`, `srt`, and Apple `container` are **not** installed on this
  host — anything needing them runs inside Docker images or the integration
  scripts under `tests/integration/`.

## Security defaults are not negotiable

Harness containers are always: non-root, `cap_drop: ALL`, `no-new-privileges`,
read-only rootfs, seccomp profile, pids/memory limits, internal network only.
**Never** mount `docker.sock`, add `host.docker.internal`/host-gateway to the
harness, or use `--privileged`. The default in-container enforcer is **nono**
(Landlock); **srt** is opt-in and needs the *surgical* relaxed seccomp profile
(`glove/runtimes/seccomp/nested-userns.json`), not a coarse one.

## Where things render

- On-disk layout: `~/.glove/` (or `$GLOVE_HOME`).
- Ring-1 policies render to
  `~/.glove/envs/<env>/sessions/<name>/enforcer/` and mount **read-only** at
  `/etc/glove/enforcer/` — never inside `/work`, never writable by the agent.

## Working agreements

- **Never `git add`, `git commit`, or `git push` without asking first.**
- Verification is real: when a change calls for running containers, actually run
  them and paste the output. If something can't be verified on this machine, say
  so and mark it "untested" rather than claiming it works.
- Keep `README.md` and `CHANGELOG.md` current with each change.
