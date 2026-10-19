"""The extension API's names and signatures (`glove.api`, `glove.api.harness`).
A change to either fails here until this snapshot changes in the same commit:
an out-of-tree extension depends on them."""

from __future__ import annotations

import dataclasses
import inspect

import glove.api
import glove.api.harness

API = {
    "ConfigError": "class(ValueError)",
    "ExtensionError": "class(ConfigError)",
    "HookContext": "dataclass(name, settings, harness, renders, trusted, session, names, slot, endpoint, "
                   "own_endpoints, active, state_dir, assets, images, libs, mount, output, input, session_dir, "
                   "work_dir, export_dirs, forwarders, grants, enforcer, enforcer_options)",
    "hook": "(fn: 'Callable') -> 'Callable'",
    "is_secret_env_name": "(name: 'str') -> 'bool'",
    "is_secret_ref": "(value: 'str') -> 'bool'",
    "keychain_service": "(ref: 'str') -> 'str | None'",
    "keychain_set": "(service: 'str', secret: 'str | None' = None) -> 'int'",
    "resolve_secret": "(value: 'str') -> 'str'",
    "existing_host_path": "(root: 'Path | None', value: 'str', kind: 'str') -> 'Path'",
    "exposes_private": "(root: 'Path | None', host: 'Path') -> 'tuple[Path, str] | None'",
    "host_path": "(root: 'Path | None', value: 'str') -> 'Path'",
    "overlaps": "(a: 'Path', b: 'Path') -> 'bool'",
    "resolve_ca_file": "(label: 'str', value: 'object', session_dir: 'Path | None') -> 'Path'",
    "HOST_GLOB": "Pattern",
    "scoped": "(session: 'str', name: 'str') -> 'str'",
    "STAGE_IGNORE": "tuple",
    "apt_bootstrap": "(probe: 'str', pkgs) -> 'str'",
    "fetch_steps": "(arch: 'dict[str, str]', name: 'str', url: 'str', verify: 'str', dest: 'str', "
                   "member: 'str' = '') -> 'list[str]'",
    "run_body": "(prefix: 'str', *steps: 'str') -> 'str'",
    "uv_steps": "(prefix: 'str') -> 'list[str]'",
    "tools_run_browsers": "(enforcer: 'str', options: 'dict[str, dict[str, Any]]') -> 'bool'",
    "active_items": "(items: 'list | None', ctx: 'dict[str, Any]') -> 'list'",
    "mcp_server": "(where: 'str', item: 'Any') -> 'dict[str, Any]'",
    "render_value": "(value: 'Any', ctx: 'dict[str, Any]', where: 'str' = '') -> 'Any'",
    "tool_names": "(where: 'str', tools: 'Any') -> 'list[str]'",
    "ExtSession": "dataclass(name, root, file, work, id, runtime, compose_file, settings, manifest)",
    "ext_session": "(name: 'str', directory: 'Path | None' = None, *, launched: 'bool' = True) -> 'ExtSession'",
    "reload_sidecar": "(s: 'ExtSession', service: 'str', env: 'Mapping[str, str]', *, wait: 'int' = 30) -> 'None'",
}
HARNESS = {
    "CONTAINER_HOME": "str",
    "INJECTED_KEY": "str",
    "TOOLS_FILE": "str",
    "AdapterContext": "dataclass(session, config_home, transcript_subdir, sessions_subdir, harness_config, enforcer, "
                      "mcp, skills, skill_links, sections, model, tool_policy, wrapped, write_roots, harness_hosts, "
                      "working_dir)",
    "HarnessModel": "dataclass(base_url, api, model, api_key_env, api_key_kind, api_key_injected, vision, "
                    "context_window, max_tokens, reasoning, extra_models)",
    "HarnessSection": "dataclass(extension, assets, data)",
    "argv_lines": "(argv: 'list[str]') -> 'str'",
    "staged_name": "(ext: 'str', src: 'Path') -> 'str'",
}


def _describe(obj) -> str:
    if dataclasses.is_dataclass(obj):
        return "dataclass(" + ", ".join(f.name for f in dataclasses.fields(obj)) + ")"
    if inspect.isclass(obj):
        return f"class({obj.__mro__[1].__name__})"
    if callable(obj):
        return str(inspect.signature(obj))
    return type(obj).__name__


def test_the_api_is_what_the_snapshot_says():
    for module, want in ((glove.api, API), (glove.api.harness, HARNESS)):
        assert sorted(module.__all__) == sorted(want), module.__name__
        assert {n: _describe(getattr(module, n)) for n in module.__all__} == want, module.__name__
