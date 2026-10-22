"""glove's extension API (`api: 2`): the only part of core an extension
imports. Each name is re-exported from where core keeps it;
`tests/test_api_surface.py` holds the list and the signatures, so a change
here is deliberate. Harness adapters import `glove.api.harness` too."""

from ..cafile import resolve_ca_file
from ..config import ConfigError, is_secret_ref, keychain_service, keychain_set, resolve_secret, secret_exists
from ..enforcers import tools_run_browsers
from ..enforcers.base import is_secret_env_name
from ..extensions import active_items, mcp_server, render_value, tool_names
from ..extsession import ExtSession, ext_session, reload_sidecar
from ..hooks import HookContext, hook
from ..image import STAGE_IGNORE, UV_HOME, apt_bootstrap, fetch_steps, run_body, uv_python_steps
from ..manifest import ExtensionError
from ..mounts import existing_host_path, host_path, overlaps
from ..naming import HOST_GLOB, scoped
from ..sessiondir import exposes_private

__all__ = [  # noqa: RUF022 (grouped, as in docs/extensions.md)
    # errors
    "ConfigError", "ExtensionError",
    # the hook protocol
    "HookContext", "hook",
    # secrets: values stay in memory
    "is_secret_env_name", "is_secret_ref", "keychain_service", "keychain_set", "resolve_secret", "secret_exists",
    # host paths
    "existing_host_path", "exposes_private", "host_path", "overlaps", "resolve_ca_file",
    # naming
    "HOST_GLOB", "scoped",
    # image building
    "STAGE_IGNORE", "UV_HOME", "apt_bootstrap", "fetch_steps", "run_body", "uv_python_steps",
    # the session's enforcer
    "tools_run_browsers",
    # rendering, with core's checks
    "active_items", "mcp_server", "render_value", "tool_names",
    # an extension's CLI
    "ExtSession", "ext_session", "reload_sidecar",
]
