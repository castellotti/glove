# Changelog

All notable changes to glove are documented here. This project follows the
phase plan in `docs/PLAN.md`.

## [0.2.0] — unreleased

### Phase 0 — bootstrap from v1

- Bootstrapped the v2 repository from the v1 working tree (`env-identity`
  branch, uncommitted changes included): `glove/`, `tests/`, `examples/`,
  `pyproject.toml`, `uv.lock`.
- Moved v1 design docs under `docs/v1/` (`DESIGN.md`, `plan-environments.md`).
- Bumped package version `0.1.0` → `0.2.0`.
- Added `README.md` (points at `docs/PLAN.md`), `CLAUDE.md` (repo conventions),
  and this `CHANGELOG.md`.
- v1 test suite passes unchanged under `uv run pytest -q`.
