"""Live check of a session directory through glove's own launch path.

    uv run python tests/integration/llm_live.py <session-dir> [prompt] [--isolation]

With GLOVE_HOME set, it:
  1. renders the session exactly as `glove up` does (`cli._open` +
     `cli._materialize_plan`: .glove/ layout, registry row, subnet);
  2. does what `glove up` does next — builds images, `compose up -d` every
     sidecar, runs the launch-time resolution (`model: auto`, `capabilities:
     auto`) from a throwaway container on the harness network, records it in
     .glove/effective.yml, and renders the harness home;
  3. instead of the interactive TUI, runs the harness once non-interactively
     (`pi -p <prompt>`) inside the same hardened, nono-wrapped container;
  4. with --isolation, runs checks in that container that nothing of the
     session directory but work/ (→ /work) and .glove/home (→ /home/agent) is
     visible.
Prints the resolved descriptor, models.json and the harness's answer, then
tears the project down. Secrets are resolved in memory exactly as `glove up`
does; nothing here prints them.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import asdict
from pathlib import Path

from glove import sessiondir
from glove.cli import _materialize_plan, _now, _open, _resolve_extensions
from glove.harnessconfig import render_home
from glove.plan import secret_env
from glove.session import _compose_base, ensure_images

ISOLATION = r"""
set -u
echo "--- ls -la /work/.. (the container root: no session dir, no .glove)"
ls -la /work/..
echo "--- stat /etc/glove; ls -la /etc/glove"
stat -c '%n %F %U:%G %a' /etc/glove; ls -la /etc/glove
echo "--- ls -la /home/agent"
ls -la /home/agent
echo "--- mounts from the host"
grep -E ' /(work|home/agent|etc/glove)' /proc/self/mountinfo | awk '{print $4, "->", $5, $6}'
leak=$(find / -xdev \( -name .glove -o -name glove-session.yml -o -name effective.yml -o -name baseline.yml \
       -o -name compose.yml -o -name template.yml \) 2>/dev/null; \
       find /work /home/agent /etc/glove \( -name .glove -o -name glove-session.yml -o -name effective.yml \
       -o -name baseline.yml -o -name compose.yml -o -name template.yml -o -name id \) 2>/dev/null)
if [ -n "$leak" ]; then echo "LEAK: $leak"; exit 1; fi
test ! -e /work/../.glove && test ! -e /home/agent/../id && test ! -e /home/agent/id || exit 1
echo "ISOLATION: PASS (no session state visible)"
"""


def main(directory: str, prompt: str, isolation: bool) -> int:
    sd, _, sid, cfg = _open(Path(directory))
    plan, _, _ = _materialize_plan(sd, sid, cfg)
    print(f"== session {sid} at {sd.root} (subnet {cfg.subnet}); compose project {plan.project}")
    secrets = secret_env(plan)
    env = {**os.environ, **secrets}
    base = _compose_base("docker", plan.project, sd.compose)
    rc = 0
    try:
        ensure_images(cfg, plan, "docker")
        sidecars = [f"glove-{plan.session}-{s.role}" for s in plan.network.sidecars]
        subprocess.run([*base, "up", "-d", *sidecars], check=True, env=env)
        print(f"== sidecars up: {', '.join(sidecars)}")
        print("== launch-time resolution (throwaway container on the harness network)")
        _resolve_extensions(plan, "docker", secrets)
        m = plan.model
        sessiondir.write_effective(sd.effective, cfg, {"at": _now(), "model": asdict(m)})
        print(f"   descriptor: model={m.model} base_url={m.base_url} api={m.api} vision={m.vision} "
              f"context_window={m.context_window} key={'yes' if m.api_key_env else 'no'}")
        render_home(cfg, plan.profile, sd.home, m, mount_plan=plan.mount_plan, comp=plan.composition)
        if cfg.harness == "pi":
            models = json.loads((sd.home / ".pi/agent/models.json").read_text())["providers"]["glove"]
            print("== models.json (provider glove):")
            print(json.dumps(models, indent=2))
        print(f"== harness answer ({cfg.harness} -p, nono-wrapped, hardened container):")
        cmd = [*plan.harness_command, "-p", prompt]
        out = subprocess.run([*base, "run", "--rm", "-T", plan.harness_service, *cmd], env=env,
                             stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=180)
        print(out.stdout.strip() or out.stderr.strip()[-2000:])
        rc = out.returncode
        if isolation:
            print("== isolation checks (same harness service: its mounts, user and hardening)")
            iso = subprocess.run([*base, "run", "--rm", "-T", "--entrypoint", "sh", plan.harness_service,
                                  "-c", ISOLATION], env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                 text=True, timeout=120)
            print(iso.stdout.strip() + (("\n" + iso.stderr.strip()[-1000:]) if iso.returncode else ""))
            rc = rc or iso.returncode
        return rc
    finally:
        subprocess.run([*base, "down", "--volumes"], env=env, capture_output=True)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--isolation"]
    sys.exit(main(args[0], args[1] if len(args) > 1 else "Reply with one short sentence.",
                  "--isolation" in sys.argv))
