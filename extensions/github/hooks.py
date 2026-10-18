"""github hooks.

- `contribute()` checks `token`/`hosts` and computes what the relay sidecar
  gets (`vars`): its settings (RELAY_SETTINGS: the gh allowlist, the git verbs,
  and each host served, github.com or a GitHub Enterprise one, with the env var
  its token arrives in); and, for `glove check`, the Enterprise hosts' token
  references and the names the relay's fence reaches (`egress_hosts`: a
  filtering egress, e.g. `corporate.allow_domains`, must admit them).
- `launch_env()` runs on the host at `glove up`: it resolves each token
  reference (`keychain:`/`env:`) in memory and hands it to the relay sidecar's
  environment for this `compose up` only (RELAY_GITHUB_TOKEN, and
  RELAY_GITHUB_TOKEN_<n> for the n-th of `hosts`, declared without a value in
  the fragment, like llm-auth's LLM_AUTH_KEY). Not a compose secret: Docker
  cannot put an environment-sourced secret file into a read-only container, and
  the sidecar keeps its read-only rootfs. relayd hands them only to gh and git.
"""

from __future__ import annotations

import re
from typing import Any

from glove.api import HookContext, hook, is_secret_ref

from . import relay_policy

GITHUB = "github.com"
TOKEN_VAR = "RELAY_GITHUB_TOKEN"
# a DNS name, lower case, not an IP literal and not github.com (that is `token`)
_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_HOST = re.compile(rf"(?=.{{1,253}}$)(?!\d+(\.\d+)*$){_LABEL}(\.{_LABEL})+")


def hosts(settings: dict[str, Any]) -> dict[str, tuple[str, str]]:
    """Every host the relay serves → (its token reference, the env var the
    token arrives in), github.com first when `token` is set."""
    out: dict[str, tuple[str, str]] = {}
    if settings.get("token"):
        out[GITHUB] = (settings["token"], TOKEN_VAR)
    for i, item in enumerate(settings.get("hosts") or [], 1):
        if not isinstance(item, dict) or set(item) != {"host", "token"}:
            raise ValueError(f"github.hosts: {item!r} must be {{host: <name>, token: keychain:<service>}}")
        host, ref = str(item["host"]).lower().rstrip("."), item["token"]
        if host == GITHUB or host.endswith(f".{GITHUB}"):
            raise ValueError(f"github.hosts: {host!r} — github.com's token is `github.token`")
        if host == "ghe.com" or host.endswith(".ghe.com"):
            # gh counts a ghe.com tenant as github.com, not Enterprise: it would
            # take GH_TOKEN (github.com's), never this host's own token
            raise ValueError(f"github.hosts: {host!r} — GitHub Enterprise Cloud (ghe.com) hosts are not supported "
                             "(GitHub Enterprise Server hosts are)")
        if not _HOST.fullmatch(host):
            raise ValueError(f"github.hosts: {item['host']!r} is not a host name")
        if host in out:
            raise ValueError(f"github.hosts: {host!r} is listed twice")
        if not isinstance(ref, str) or not is_secret_ref(ref):
            raise ValueError(f"github.hosts: {host}'s token must be a reference (keychain:<service> or env:<VAR>), "
                             "never the value")
        out[host] = (ref, f"{TOKEN_VAR}_{i}")
    if not out:
        raise ValueError("github needs a token: `token` (github.com) or `hosts` (GitHub Enterprise)")
    return out


@hook
def contribute(ctx: HookContext) -> dict[str, Any]:
    s = ctx.settings
    served = hosts(s)
    settings = {"allow": s.get("allow") or [], "git": s["git"], "hosts": {h: var for h, (_, var) in served.items()}}
    fence = relay_policy.fence_hosts(settings)
    return {
        "vars": {"settings": settings, "tokens": [var for _, var in served.values()]},
        # what the fence tunnels to, for `glove check` against a filtering egress
        "egress_hosts": [f"*{h}" if h.startswith(".") else h for h in fence],
        # for `glove check` (`token` is a secret setting: core checks it already)
        "secret_refs": {f"hosts.{h}": ref for h, (ref, _) in served.items() if h != GITHUB},
    }


@hook
def launch_env(ctx: HookContext, resolve_secret) -> dict[str, Any]:
    env = {}
    for host, (ref, var) in hosts(ctx.settings).items():
        token = resolve_secret(ref).strip()
        if not token:
            raise ValueError(f"github: the token for {host} resolves to an empty value")
        env[var] = token
    return {"env": env}
