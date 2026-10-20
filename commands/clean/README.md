# `glove clean`

Removes what glove left on Docker and Podman.

- **Stacks of sessions that no longer exist here.** A session's stack is its
  compose project `glove-<id>`: the containers, networks and volumes compose
  labelled with it. Their stopped containers (with their anonymous volumes,
  which no later container can mount) and networks go.
- **Volumes only when the session is provably gone:** its registry row's
  directory now holds another session (re-launched under a new id). A missing
  directory may have moved, and a `glove-<v3 id>` project with no row may be
  another `GLOVE_HOME`'s (an integration test's): their volumes stay, with a
  line saying why, unless `--volumes`.
- A live session's stack, a stack with any container not `exited`/`dead`
  (running, starting, paused, …), and anything that is not a `glove-<v3 id>`
  project are never touched.
- It lists first, then asks. `--dry-run` only lists, `--yes` skips the
  question, `--runtime docker|podman` looks at one runtime (default: each on
  `PATH`; one that does not answer is reported and skipped).

`glove gc` removes the registry rows and exports of the same sessions.
