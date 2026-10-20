"""What a command (`commands/<name>/cli.py`, in-tree only) imports from core
besides `glove.api`: the session machinery and the core names commands use."""

from .. import __version__ as VERSION
from ..config import secret_exists
from ..doctor import extension_checks, run_doctor, worst_status
from ..enforcers import get_enforcer
from ..enforcers.base import default_enforcer
from ..extensions import discover
from ..harness import get_profile, known_harnesses
from ..naming import project_name
from ..plan import build_session_plan, secret_refs
from ..quarantine import supported as quarantine_supported
from ..registry import RegistryError, glove_home, load_registry
from ..registry import remove as remove_rows
from ..runtimes import get_runtime, known_runtimes
from ..runtimes.base import Check
from ..session import build_forwarder, build_harness, probe_direct
from ..sessiondir import (
    ID_RE,
    PLACEHOLDER,
    SCHEMA_VERSION,
    SessionDir,
    SessionError,
    autodetect_provider,
    placeholders_left,
    template_drift,
)
from ..sessiondir import find as find_session
from ..sessiondir import load_file as load_session_file
from ..sessiondir import materialize as materialize_session
from ..sessionops import (
    DIR_ARG,
    console,
    ensure_home,
    err,
    fail,
    mark_downloads,
    open_session,
    print_checks,
    print_extensions,
    row_state,
    sync_registry,
)

__all__ = ["DIR_ARG", "ID_RE", "PLACEHOLDER", "SCHEMA_VERSION", "VERSION", "Check", "RegistryError", "SessionDir",
           "SessionError", "autodetect_provider", "build_forwarder", "build_harness", "build_session_plan", "console",
           "default_enforcer", "discover", "ensure_home", "err", "extension_checks", "fail", "find_session",
           "get_enforcer", "get_profile", "get_runtime", "glove_home", "known_harnesses", "known_runtimes",
           "load_registry", "load_session_file", "mark_downloads", "materialize_session", "open_session",
           "placeholders_left", "print_checks", "print_extensions", "probe_direct", "project_name",
           "quarantine_supported", "remove_rows", "row_state", "run_doctor", "secret_exists", "secret_refs",
           "sync_registry", "template_drift", "worst_status"]
