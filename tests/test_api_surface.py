"""The extension API's names and signatures (`glove.api`, `glove.api.harness`,
`glove.api.commands`). A change to any fails here until this snapshot changes in the same commit:
an out-of-tree extension depends on them."""

from __future__ import annotations

import dataclasses
import inspect

import glove.api
import glove.api.commands
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
    "secret_exists": "(value: 'str') -> 'tuple[bool, str]'",
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
COMMANDS = {
    "DIR_ARG": "ArgumentInfo",
    "HardeningError": "class(ValueError)",
    "ID_RE": "Pattern",
    "Check": "dataclass(name, status, detail)",
    "IKNOW": "OptionInfo",
    "OPTION_SECTIONS": "dict",
    "PLACEHOLDER": "str",
    "RegistryError": "class(ValueError)",
    "SCHEMA_VERSION": "int",
    "SESSION_FILE": "str",
    "SessionDir": "dataclass(root)",
    "SessionError": "class(ConfigError)",
    "VERSION": "str",
    "autodetect_provider": "() -> 'str'",
    "build_session_plan": "(cfg: 'Config', *, home_dir: 'str', cwd: 'str | None' = None, uid: 'int | None' = None, "
                          "gid: 'int | None' = None, resume: 'bool' = False, session_id: 'str | None' = None, "
                          "state_dir: 'str | None' = None, session_dir: 'str | None' = None) -> 'SessionPlan'",
    "build_forwarder": "(provider: 'str', *, force: 'bool' = False) -> 'None'",
    "build_harness": "(provider: 'str', profile: 'HarnessProfile', *, apt_packages: 'list[str] | None' = None, "
                     "pip_packages: 'list[str] | None' = None, enforcer: 'str' = 'nono', "
                     "plan: 'SessionPlan | None' = None, force: 'bool' = False) -> 'str'",
    "console": "Console",
    "control_dir": "(session_id: 'str') -> 'Path'",
    "default_enforcer": "(runtime: 'str') -> 'str'",
    "discover": "(in_tree: 'Path | None' = None) -> 'dict[str, Manifest]'",
    "ensure_home": "() -> 'None'",
    "err": "Console",
    "extension_checks": "(requested: 'dict', *, harness: 'str', comp: 'Composition | None' = None, probe=None, "
                        "**session) -> 'list[Check]'",
    "fail": "(msg: 'str', code: 'int' = 1) -> 'typer.Exit'",
    "find_session": "(path: 'str | Path | None' = None) -> 'SessionDir'",
    "get_enforcer": "(name: 'str')",
    "get_profile": "(name: 'str') -> 'HarnessProfile'",
    "get_runtime": "(name: 'str')",
    "glove_home": "() -> 'Path'",
    "known_harnesses": "() -> 'list[str]'",
    "known_runtimes": "() -> 'list[str]'",
    "load_registry": "() -> 'list[SessionEntry]'",
    "load_session_file": "(sd: 'SessionDir') -> 'dict[str, Any]'",
    "mark_downloads": "(sd: 'SessionDir') -> 'quarantine.Marked | None'",
    "materialize_session": "(spec: 'str', dest: 'Path') -> 'tuple[SessionDir, str]'",
    "materialize_plan": "(sd: 'SessionDir', sid: 'str', cfg, *, resume: 'bool' = False, session: 'str | None' = None, "
                        "home: 'bool' = True, overrides: 'frozenset[str]' = frozenset())",
    "observe_dir": "(session_id: 'str') -> 'Path'",
    "one_resume": "(resume: 'bool', session: 'str | None') -> 'None'",
    "open_session": "(dir_arg: 'Path | None', *, register: 'bool' = True, check_runtime: 'bool' = False)",
    "placeholders_left": "(raw: 'Any', path: 'str' = '') -> 'list[str]'",
    "print_checks": "(title: 'str', checks: 'list') -> 'None'",
    "print_extensions": "(plan) -> 'None'",
    "probe_direct": "(provider: 'str', url: 'str', *, method: 'str' = 'GET', body: 'dict | None' = None, "
                    "headers: 'dict[str, str] | None' = None) -> 'tuple[int, str]'",
    "project_name": "(session: 'str') -> 'str'",
    "quarantine_supported": "() -> 'bool'",
    "read_effective": "(path: 'Path') -> 'tuple[Config | None, dict[str, Any]]'",
    "remove_rows": "(session_ids: 'set[str]') -> 'int'",
    "remove_state": "(sd: 'SessionDir') -> 'None'",
    "row_state": "(e: 'reg.SessionEntry') -> 'str'",
    "run_doctor": "(*, runtime: 'str' = 'docker', enforcer: 'str' = 'nono', include_container_probes: 'bool' = True) "
                  "-> 'list[Check]'",
    "secret_exists": "(value: 'str') -> 'tuple[bool, str]'",
    "secret_refs": "(plan: 'SessionPlan') -> 'list[tuple[str, str]]'",
    "stop": "(sd: 'SessionDir', sid: 'str', provider: 'str | None', *, wipe: 'bool', mark: 'bool' = True) -> 'None'",
    "sync_registry": "(sd: 'SessionDir', sid: 'str', raw: 'dict', *, check_runtime: 'bool' = False) "
                     "-> 'reg.SessionEntry'",
    "template_drift": "(sd: 'SessionDir') -> 'tuple[str, str] | None'",
    "worst_status": "(checks: 'list[Check]') -> 'str'",
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
    for module, want in ((glove.api, API), (glove.api.harness, HARNESS), (glove.api.commands, COMMANDS)):
        assert sorted(module.__all__) == sorted(want), module.__name__
        assert {n: _describe(getattr(module, n)) for n in module.__all__} == want, module.__name__
