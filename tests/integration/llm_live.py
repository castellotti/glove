"""Live check of the `llm` extension through glove's own launch path.

Run from a directory `glove init <harness>` was run in (GLOVE_HOME set). It:
  1. renders the session with the real CLI (`glove <harness> --dry-run`);
  2. does what `glove run` does after that — builds images, `compose up -d`
     every sidecar, runs the launch-time resolution (`model: auto`,
     `capabilities: auto`) from a throwaway container on the harness network,
     and renders the harness home;
  3. instead of the interactive TUI, runs the harness once non-interactively
     (`pi -p <prompt>`) inside the same hardened, nono-wrapped container.
Prints the resolved descriptor, models.json and the harness's answer, then
tears the project down. Secrets are resolved in memory exactly as `glove run`
does; nothing here prints them.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from typer.testing import CliRunner

from glove.cli import _home_dir, _resolve_extensions, app
from glove.config import resolve
from glove.harnessconfig import render_home
from glove.plan import build_session_plan, secret_env
from glove.registry import find_env_id, session_dir
from glove.session import _compose_base, ensure_images


def main(harness: str, prompt: str) -> int:
    r = CliRunner().invoke(app, ["run", harness, "--dry-run"])
    if r.exit_code != 0:
        print(r.output)
        return 1
    env_id = find_env_id(os.getcwd(), harness)
    sdir = session_dir(env_id, env_id)
    cfg = resolve(env_config_path=Path(os.environ["GLOVE_HOME"]) / "envs" / env_id / "glove.yaml",
                  overrides={"name": env_id})
    home = _home_dir(cfg, sdir)
    plan = build_session_plan(cfg, env_id=env_id, home_dir=str(home), cwd=os.getcwd(), state_dir=str(sdir / "ext"))
    plan.policies_host_dir = str(sdir / "enforcer")
    secrets = secret_env(plan)
    env = {**os.environ, **secrets}
    base = _compose_base("docker", plan.project, sdir / "docker-compose.yml")
    try:
        ensure_images(cfg, plan, "docker")
        sidecars = [f"glove-{plan.session}-{s.role}" for s in plan.network.sidecars]
        subprocess.run([*base, "up", "-d", *sidecars], check=True, env=env)
        print(f"== sidecars up: {', '.join(sidecars)}")
        print("== launch-time resolution (throwaway container on the harness network)")
        _resolve_extensions(plan, "docker", secrets)
        m = plan.model
        print(f"   descriptor: model={m.model} base_url={m.base_url} api={m.api} vision={m.vision} "
              f"context_window={m.context_window} key={'yes' if m.api_key_env else 'no'}")
        render_home(cfg, plan.profile, home, m, mount_plan=plan.mount_plan, comp=plan.composition)
        if harness == "pi":
            models = json.loads((home / ".pi/agent/models.json").read_text())["providers"]["glove"]
            print("== models.json (provider glove):")
            print(json.dumps(models, indent=2))
        print(f"== harness answer ({harness} -p, nono-wrapped, hardened container):")
        cmd = [*plan.harness_command, "-p", prompt]
        out = subprocess.run([*base, "run", "--rm", "-T", plan.harness_service, *cmd], env=env,
                             stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180)
        print(out.stdout.strip() or out.stderr.strip()[-2000:])
        return out.returncode
    finally:
        subprocess.run([*base, "down", "--volumes"], env=env, capture_output=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "Reply with one short sentence."))
