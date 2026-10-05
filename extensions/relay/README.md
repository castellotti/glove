# relay

A library extension, never selected on its own. An extension that relays
commands (`github`, `ssh`) requires it, and it is then added automatically. A
relay runs a few named commands for the harness in a sidecar that holds the
credential. Neither the credential nor a network route enters the sandbox, and
every other shell command stays offline.

It brings two things:

- **`glove-relay`**, the client, baked into the harness image at
  `/opt/glove/bin/glove-relay`. Usage: `glove-relay <channel> <command> args…`.
  Consumers install one wrapper per command; for example, `github`'s `gh` runs
  `exec /opt/glove/bin/glove-relay github gh "$@"`.
- **The `relayd` image** (`image/`): `relayd.py` (the sidecar half), plus git,
  ssh and the official `gh` that relayed commands run. The base image is pinned by
  digest and the `gh` release by version and SHA-256. Each consumer runs this
  image with its own policy file, bound read-only.

## The channel: files and FIFOs, not a socket

Glove's seccomp filter below srt (`nono+srt`, `srt`) forbids creating Unix
sockets, for the harness and for every command it runs. A relay therefore talks
over a **channel**: a session tmpfs volume at `/run/glove/<name>`, mounted in
both the harness and the consumer's sidecar. Every enforcer lets the harness and
its commands write there, and grants no network for it. Core provides channels
(`channels:` in a manifest, in-tree or trusted extensions only).

One request:

1. The client makes `req/<random id>/` (mode 0700). It writes `argv`
   (NUL-separated) and `cwd` there, creates the FIFOs `1`, `2` and `rc`, and
   writes the id to the `door` FIFO.
2. relayd opens the request directory without following links. It asks the
   policy for the command to run, or for a refusal. It runs the command with
   stdout and stderr on the FIFOs and stdin on `/dev/null`, writes the exit code
   to `rc`, and removes the directory.
3. A refusal reaches the agent as `glove relay: refused: <why>`, with exit code
   126.

Relayed commands get **no stdin**, so input goes in a file under `/work`. If
the client goes away (an aborted tool call), relayd kills the command. A command
that runs past `timeout` is stopped with exit code 124. At most `--max` commands
run at once (a request past that gets `busy`), and at most four times that may
wait for their client to open its FIFOs: more are dropped, and a request whose
FIFOs aren't all open within 10s is dropped and its directory removed.

## The policy

The consumer supplies the policy, a Python file that relayd loads by path:

- `COMMANDS`: the command names it serves.
- `HOSTS`: the hosts its commands may reach, either exact (`github.com`) or a
  suffix (`.githubusercontent.com`).
- `setup(ctx)`: builds the children's environment from nothing.
- `prepare(req, env)`: returns `(argv, extra env)` or raises its `Refused`.

`req.file(path)` opens a file argument inside `/work` and returns `/dev/fd/<n>`
for the child. It checks the file it actually opened, through that file's
`/proc` link, so swapping in a symlink afterwards doesn't help. `req.directory`
validates a destination under `/work`.

## The egress fence

Children reach the network only through relayd's in-process CONNECT proxy on
`127.0.0.1`. It tunnels to the session's egress proxy (`--upstream`, or with
`observe` a gate in front of it) for the policy's `HOSTS` on port 443, and
refuses everything else, whatever arguments the policy let through. A
connection that hasn't sent its `CONNECT` request within 10s is closed.
