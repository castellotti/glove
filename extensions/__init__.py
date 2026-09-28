"""First-party glove extensions (in-tree modules).

Each ``extensions/<name>/`` directory holds an ``extension.yml`` manifest plus
its assets. Core (``glove``) loads them by path and must never import this
package; ``uv run lint-imports`` enforces that boundary.
"""
