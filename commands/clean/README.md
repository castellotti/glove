# `glove clean`

Removes what glove left on Docker and Podman.

- **Dead sessions' stacks.** A session's stack is its compose project
  `glove-<id>`: the containers, networks and volumes compose labelled with it.
  The stack is dead when its session no longer exists: the registry row's
  directory is gone or holds another session now (re-launched under a new
  id), or there is no row (a `glove-<v3 id>` project of another `GLOVE_HOME`,
  such as an integration test's). Nothing of it can be restarted, so all of
  it goes, volumes included.
- A running stack, a live session's stack, and anything that is not a
  `glove-<v3 id>` project are never touched.
- It lists first, then asks. `--dry-run` only lists, `--yes` skips the
  question, `--runtime docker|podman` looks at one runtime (default: each on
  `PATH`; one that does not answer is reported and skipped).

`glove gc` (core) removes the registry rows and exports of the same sessions.
