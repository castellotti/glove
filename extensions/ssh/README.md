# ssh

Lets the agent run `ssh <host> <command>` from its shell, to hosts the session
names on your LAN. The command is relayed (see [`relay`](../relay/README.md)) to a
sidecar that holds the private key in an `ssh-agent`. The key never enters the
harness, and the harness gets no route to the LAN: only the sidecar reaches the
hosts, each through its own forwarder. Works with every harness and every
enforcer.

```yaml
extensions:
  ssh:
    key: keychain:<service>              # a private key: PEM, or base64 of it (one line)
    hosts:
      - { name: build, to: "<host>:22", user: <user> }
    known_hosts: local/known_hosts       # host keys, checked strictly (never learned)
    # timeout: 600
```

- **The key.** `glove keychain set` stores one line, so store the key
  base64-encoded: run `base64 < key | tr -d '\n'` and paste the result. Use a
  key made for the session and authorize it only on the hosts listed (for
  example with `restrict` and `from=` options in `authorized_keys`).
- **`known_hosts`.** Run `ssh-keyscan -p <port> <host> > local/known_hosts`,
  then check the keys against the host. The file must sit inside the session
  directory. It is copied into the extension's state and bound read-only into
  the sidecar.

## What the agent sees

- `/usr/local/bin/ssh` relays every call.
- The brief names the hosts and the rules.
- `ssh build 'uname -a && df -h'` runs on the host and returns its output and
  exit code.
- There is no interactive shell, no TTY and no stdin, so pass the whole command.

## The policy (`relay_policy.py`)

- **Destinations.** Only the listed hosts are reachable, by name (`build` or
  `<user>@build` with its configured user). ssh dials that host's forwarder,
  `glove-<id>-ssh-<name>`, and checks the host key under the host's own name
  (`HostKeyAlias`, `[host]:port` off port 22) against the session's
  `known_hosts` (`StrictHostKeyChecking=yes`, no other known-hosts file).
- **Options are an allowlist:** `-q`, `-v`, `-T`, `-n`, `-4`, `-6`, `-C`, and
  `-o` only for `ConnectTimeout`, `ServerAliveInterval`, `ServerAliveCountMax`,
  `BatchMode` and `LogLevel`.
- **Refused:**
  - port forwarding (`-L`/`-R`/`-D`/`-W`) and jump hosts;
  - `ProxyCommand` and other `-o` keys;
  - `-i`, `-F` and agent or X11 forwarding;
  - control sockets, local commands and a TTY.
- **Pinned options.** Fixed options come first in argv: `-F /dev/null`, batch
  mode, no passwords, `ClearAllForwardings`, `ProxyCommand=none`, and the agent
  socket. ssh keeps the first value it sees for a key, so an allowed `-o` can't
  override them.

## The sidecar (`ssh`) and its forwarders

- **Image:** relay's image (now with `openssh-client` and `libnss-wrapper`),
  running relayd with `relay_policy.py` bound read-only.
- **Hardening:** core's full sidecar set.
- **Network:** the sidecar sits on `sshnet` only. It mounts no `/work`; file
  arguments are refused.
- **Forwarders.** Each host gets one forwarder,
  `glove-<id>-ssh-<name>:22`, which dials exactly `to` over core's `lan`
  network (routable; only `via: lan` forwarders may join it). It is never on
  the harness network. With `observe`, each forwarder is a TCP gate:
  `client: ssh`, `tool: ssh`, `scope: lan`. Every connection is a flow, and
  `glove filter` can block it.
- **The key** reaches the sidecar's environment at `compose up` (`launch_env`
  in `hooks.py`, resolved in memory). It is loaded into an `ssh-agent` on the
  sidecar's tmpfs, and relayed `ssh` uses it through the agent.
- **Passwd entry:** ssh needs a passwd entry for the session uid, so
  `nss_wrapper` serves one from `/tmp` (the rootfs is read-only).

## Tested

Run `SSH_TEST_HOST=<host> SSH_TEST_USER=<user> SSH_KEYCHAIN=<service> bash
tests/integration/test_ssh.sh` (optionally with `OBSERVE=1`). It drives real
agent tool calls against a LAN host you name, under nono and nono+srt, and
checks that:

- the channel is there, and the key is not in the harness;
- `ssh <host> <command>` runs as the configured user, and the remote exit code
  comes back;
- every refusal holds;
- a shell command can't reach the host;
- the sidecar reaches the host only through its forwarder;
- with observe, the flows are `client: ssh`, `scope: lan`.
