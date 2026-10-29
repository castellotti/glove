"""`glove check` — validate a session and probe what it needs, launching nothing."""

from __future__ import annotations

from functools import partial
from pathlib import Path

import typer
import yaml

from glove.api import ConfigError, secret_exists
from glove.api.commands import (
    DIR_ARG,
    PLACEHOLDER,
    SCHEMA_VERSION,
    Check,
    build_session_plan,
    extension_checks,
    fail,
    get_runtime,
    open_session,
    placeholders_left,
    print_checks,
    probe_direct,
    run_doctor,
    secret_refs,
    session_bind_layer,
    template_drift,
)

RANK = 4  # its place in `glove --help` (commands/README.md)


def command(
    directory: Path | None = DIR_ARG,
    no_container: bool = typer.Option(False, "--no-container", help="skip container probes (host-only, fast)"),
    offline: bool = typer.Option(False, "--offline", help="contact nothing the session reaches (e.g. the LLM server)"),
) -> None:
    """Validate the session file, check its secrets exist (never reads them),
    run doctor for its runtime, enforcer and extensions, and (unless --offline
    or --no-container) ask the LLM server for its models from a throwaway
    container (never from this machine)."""
    try:
        sd, raw, sid, cfg = open_session(directory, register=False)
    except (ConfigError, ValueError) as e:
        raise fail(str(e)) from e
    checks: list[Check] = [Check("session file", "ok", f"{sd.file} (schema v{SCHEMA_VERSION})")]
    plan = None
    todo = placeholders_left(raw)
    if todo:
        checks.append(Check("placeholders", "fail", f"still {PLACEHOLDER}: {', '.join(todo)}"))
    else:
        try:
            plan = build_session_plan(cfg, home_dir=str(sd.home), cwd=str(sd.work), state_dir=str(sd.ext),
                                      session_dir=str(sd.root), bind_layer=session_bind_layer(cfg))
            checks.append(Check("plan", "ok", "extensions: " + ", ".join(a.name for a in plan.composition.active)))
            try:  # in memory: every render-time invariant, for this runtime
                n = len(yaml.safe_load(get_runtime(cfg.runtime).render(plan, sd.state).compose_yaml)["services"])
                checks.append(Check("render", "ok", f"{cfg.runtime}: {n} services"))
            except (ConfigError, ValueError, NotImplementedError) as e:
                checks.append(Check("render", "fail", str(e)))
            for label, ref in secret_refs(plan):
                ok, detail = secret_exists(ref)
                checks.append(Check(f"secret {label}", "ok" if ok else "fail", f"{ref}: {detail}"))
        except (ConfigError, ValueError) as e:
            checks.append(Check("plan", "fail", str(e)))
    drift = template_drift(sd)
    if drift is not None:
        checks.append(Check("template", "warn",
                            f"{drift[0]} changed since `glove new`; review with `glove new --diff`"))
    try:
        checks += run_doctor(runtime=cfg.runtime, enforcer=cfg.enforcer, include_container_probes=not no_container)
        checks += extension_checks(cfg.extensions, harness=cfg.harness, comp=plan and plan.composition,
                                   session_dir=sd.root, work_dir=sd.work, enforcer=cfg.enforcer,
                                   enforcer_options=cfg.enforcer_options,
                                   probe=None if offline or no_container else partial(probe_direct, cfg.provider))
    except ValueError as e:
        checks.append(Check("doctor", "fail", str(e)))
    print_checks(f"[bold]glove check[/bold]  {sid}  ({sd.root})", checks)
