"""What a command (`commands/<name>/cli.py`, in-tree only) imports from core
besides `glove.api`: the session machinery and the core names commands use."""

from .. import __version__ as VERSION
from ..naming import project_name
from ..registry import RegistryError, load_registry
from ..sessiondir import ID_RE, SessionDir

__all__ = ["ID_RE", "VERSION", "RegistryError", "SessionDir", "load_registry", "project_name"]
