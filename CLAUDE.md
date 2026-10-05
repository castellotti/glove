# Repo conventions for Claude Code

`glove` v3 — a sandbox launcher for agentic coding harnesses. It runs a chosen
harness (Pi, Mistral Vibe, Claude Code) inside a hardened container with an
in-container kernel enforcer wrapping the agent and every command it runs.

## Toolchain

- Python ≥ 3.11, managed with **uv**. Never call `pip` or a bare `python`.
  - `uv sync` — install/refresh the environment.
  - `uv run ruff check glove harnesses extensions tests` — lint (must be clean before moving on).
  - `uv run pytest -q` — run the test suite (must be green before moving on).
  - `uv run glove …` — run the CLI.
- Docker Desktop and `podman` (an applehv machine; `podman machine start`) are
  installed. `nono`, `srt` and Apple `container` are **not** — anything needing
  them runs inside the images or the integration scripts under `tests/integration/`.

## Security defaults are not negotiable

Harness containers are always: non-root, `cap_drop: ALL`, `no-new-privileges`,
read-only rootfs, seccomp profile, pids/memory limits, internal network only.
**Never** mount `docker.sock`, add `host.docker.internal`/host-gateway to the
harness, or use `--privileged`. The default in-container enforcer is
**nono+srt** on Docker (srt around the harness, nono/Landlock around every
command) and **nono** on Podman; the srt enforcers need the *surgical* relaxed
seccomp profile (`glove/runtimes/seccomp/nested-userns.json`), not a coarse one,
and glove's own `apply-seccomp` re-denies namespaces/mounts below srt.

## Where things render

- A session is a directory: `glove-session.yml`, `work/` (→ `/work`) and
  `.glove/` (0700). Global state: `~/.glove/` (or `$GLOVE_HOME`): `config.yml`,
  `registry.json`, `observe/<id>/`, `control/<id>/`.
- Ring-1 policies render to `<session-dir>/.glove/enforcer/` and mount
  **read-only** at `/etc/glove/enforcer/` — never inside `/work`, never writable
  by the agent.

## Working agreements

- **Never `git add`, `git commit`, or `git push` without asking first.**
- Verification is real: when a change calls for running containers, actually run
  them and paste the output. If something can't be verified on this machine, say
  so and mark it "untested" rather than claiming it works.
- Keep `README.md` and `CHANGELOG.md` current with each change.

## Change workflow (always)

Work in rounds: **one branch and one PR per round**, never stacked PRs (stacked
merges once left #20–#24 off `main`). A round's plan lives in `docs/planning/`
(git-ignored, private). Each phase of the round is one commit:

1. Implement the phase; ruff clean and pytest green.
2. `/code-review` the uncommitted diff and fix what it finds, then `/simplify`.
3. Ask, then commit the phase.
4. Update the planning documents: results go into the completed plan, and what
   future plans need goes into theirs. Add every skipped finding, suggestion,
   untested check and missing test to `docs/planning/TODO.md`, and prune the
   items the phase implemented.
5. The operator runs `/compact` before the next phase starts.

Live verification runs once at the end of the round, then (after asking) push
and open the round's single PR to `main`.
