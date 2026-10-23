"""Live: a failing exit check stops the sidecars (fail closed).

Run by `FAIL_EXIT=1 tests/integration/test_egress.sh tor|vpn`: the egress's
`host_check_url` names a page that is no IP address (`on.quad9.net`), so the
exitcheck hook confirms the exit's IP and then cannot rule out a leak. Checks:

  1. `start_sidecars` raises VerifyError for `exit-confirmed`, with the hook's
     ConfigError message;
  2. glove itself stopped every sidecar (listed before this driver tears down).

Prints PASS/FAIL per check; exit 0 only if all pass.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from live_common import LiveSession, _materialize, check, preflight, summary

from glove.session import _compose_base, compose_process_env, ensure_images, start_sidecars, teardown
from glove.verify import VerifyError


def main(directory: str) -> int:
    sd, sid, cfg, plan, secrets = _materialize(Path(directory))
    s = LiveSession(sd, sid, cfg, plan, secrets, compose_process_env(cfg.provider, secrets),
                    _compose_base(cfg.provider, plan.project, sd.compose))
    print(f"== session {sid} (runtime {s.rt}, egress {plan.composition.slots['egress'].name})")
    try:
        preflight(sd, cfg, plan)
        ensure_images(cfg, plan, s.rt)
        try:
            start_sidecars(plan, sd.compose, provider=s.rt, env=s.env)
            check("verify failed (exit-confirmed)", False, "start_sidecars returned: the check passed")
        except VerifyError as e:
            msg = str(e)
            check("verify failed (exit-confirmed)", "exit-confirmed" in msg, msg[-300:])
            check("the hook's own reason shown", "leak cannot be ruled out" in msg)
        running = subprocess.run([s.rt, "ps", "-q", "--filter", f"name=glove-{sid}-"],
                                 capture_output=True, text=True).stdout.split()
        check("glove stopped every sidecar", not running, f"running: {running}")
    finally:
        teardown(sid, provider=s.rt, wipe=True)
    return summary()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
