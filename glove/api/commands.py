"""What a command (`commands/<name>/cli.py`, in-tree only) imports from core
besides `glove.api`: the session machinery and the core names commands use."""

from .. import __version__ as VERSION
from ..config import secret_exists
from ..doctor import extension_checks, run_doctor, worst_status
from ..enforcers import OPTION_SECTIONS, get_enforcer
from ..enforcers.base import default_enforcer
from ..exports import export_dirs
from ..extensions import call_hook, discover
from ..extsession import run_teardown
from ..hardening import HardeningError
from ..harness import get_profile, known_harnesses
from ..harnessconfig import harness_model, render_home
from ..naming import project_name
from ..plan import build_session_plan, secret_env, secret_refs
from ..quarantine import supported as quarantine_supported
from ..registry import RegistryError, glove_home, load_registry
from ..registry import remove as remove_rows
from ..runtimes import get_runtime, known_runtimes
from ..runtimes.base import Check
from ..session import (
    SubnetTaken,
    build_forwarder,
    build_harness,
    clear_stale_harness,
    launch,
    probe_direct,
    probe_http,
    with_headers,
)
from ..sessiondir import (
    ID_RE,
    PLACEHOLDER,
    SCHEMA_VERSION,
    SESSION_FILE,
    SessionError,
    autodetect_provider,
    placeholders_left,
    read_effective,
    remove_state,
    template_drift,
    write_effective,
)
from ..sessiondir import find as find_session
from ..sessiondir import load_file as load_session_file
from ..sessiondir import materialize as materialize_session
from ..sessionops import (
    DIR_ARG,
    IKNOW,
    console,
    conversations,
    ensure_home,
    err,
    fail,
    mark_downloads,
    materialize_plan,
    now,
    one_resume,
    open_session,
    print_checks,
    print_extensions,
    row_state,
    stop,
    sync_registry,
)

__all__ = ["DIR_ARG", "ID_RE", "IKNOW", "OPTION_SECTIONS", "PLACEHOLDER", "SCHEMA_VERSION", "SESSION_FILE", "VERSION",
           "Check", "HardeningError", "RegistryError", "SessionError", "SubnetTaken", "autodetect_provider",
           "build_forwarder", "build_harness", "build_session_plan", "call_hook", "clear_stale_harness", "console",
           "conversations", "default_enforcer", "discover", "ensure_home", "err", "export_dirs", "extension_checks",
           "fail", "find_session", "get_enforcer", "get_profile", "get_runtime", "glove_home", "harness_model",
           "known_harnesses", "known_runtimes", "launch", "load_registry", "load_session_file", "mark_downloads",
           "materialize_plan", "materialize_session", "now", "one_resume", "open_session", "placeholders_left",
           "print_checks", "print_extensions", "probe_direct", "probe_http", "project_name", "quarantine_supported",
           "read_effective", "remove_rows", "remove_state", "render_home", "row_state", "run_doctor", "run_teardown",
           "secret_env", "secret_exists", "secret_refs", "stop", "sync_registry", "template_drift", "with_headers",
           "worst_status", "write_effective"]
