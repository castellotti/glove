# glove

`glove` is a Python CLI that launches an agentic coding harness (Pi or Mistral
Vibe first; Claude Code later) inside a **sandbox**, presents the harness's
normal TUI in your terminal, and guarantees that the harness — and every shell
command, extension, skill, or MCP server it spawns — can only touch the host
directories you explicitly exposed, can only reach the network endpoints you
explicitly allowed, and cannot escalate privilege.

The sandbox is *distributed as a container image* (Docker first) but the
security does not rest on the container alone: a kernel-level capability
sandbox (nono/Landlock by default) runs *inside* the container and wraps every
command the agent executes.

## Status

This is **glove v2**, bootstrapped from the v1 session manager. The complete,
research-backed design and phase plan is the authority for this work:

- **[docs/PLAN.md](docs/PLAN.md)** — the specification (three-ring
  architecture, hardening set, enforcer/runtime/browser layers, phases).
- **[docs/research/](docs/research/)** — the experiments and probe scripts that
  justify the plan's decisions (`bash docs/research/run-all.sh` to re-verify).
- **[docs/v1/](docs/v1/)** — the original v1 design docs, kept for reference.

### Phase status

| Phase | Scope | Status |
|---|---|---|
| 0 | Bootstrap from v1 (code, tests, docs) | ✅ done |
| 1 | Runtime layer + hardening + `glove doctor` | ⬜ not started |
| 2 | nono enforcer + Pi integration | ⬜ not started |
| 3 | Vibe integration | ⬜ not started |
| 4 | srt enforcer (opt-in) | ⬜ not started |
| 5 | Browser providers | ⬜ not started |
| 6 | Runtime stubs, podman, docs | ⬜ not started |

### Runtime / enforcer / browser support

| Component | Option | Status |
|---|---|---|
| Runtime | docker | v1-carried, hardening in Phase 1 |
| Runtime | podman | planned, untested (no podman on host) |
| Runtime | apple-container / gondolin / utm | stub only |
| Enforcer | nono (Landlock) — default | planned Phase 2 |
| Enforcer | srt (bubblewrap) — opt-in | planned Phase 4 |
| Enforcer | none (ring 0 only) | debug |
| Browser | host-mcp | v1-proven |
| Browser | host-server | planned Phase 5 |
| Browser | sidecar-desktop / vm-desktop | spec only |

## Toolchain

Python ≥ 3.11 managed with [uv](https://docs.astral.sh/uv/):

```sh
uv sync
uv run pytest -q
uv run glove --help
```

## Quick start (target UX, see PLAN §7.3)

```sh
cd ~/src/service-a
glove init pi
glove pi --name TICKET-1234 --add-dir ~/src/shared-lib:ro --net service --browser host-mcp
```
