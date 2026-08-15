# Writing a foSSH module

foSSH is a platform. Telemetry is its flagship module — the reason most
people install it — but it is a module, and yours sits beside it on the
same terms.

A module is a program that reads a line and writes a line. That is the
whole interface. It can be written in anything.

## The shortest possible module

```sh
#!/bin/sh
# /usr/libexec/fossh-hello
while IFS= read -r line; do
  id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9]*\).*/\1/p')
  printf '{"id":%s,"ok":true,"result":{"greeting":"hello"}}\n' "$id"
done
```

```toml
# /etc/fossh/modules.d/hello.toml
namespace = "hello"
name = "Hello"
description = "Proves the module system works."
exec = "/usr/libexec/fossh-hello"
```

```
$ echo '{"id":1,"method":"hello.greet"}' | /usr/libexec/fossh-agent
{"id":1,"ok":true,"result":{"greeting":"hello"}}
```

That is a working module. Everything below is detail.

## How it fits together

Every method in foSSH is `namespace.verb` — `telemetry.query`,
`integrations.add`, `providers.list`. A namespace is what a module
owns. When the agent receives a method whose namespace it does not
serve itself, it looks for a module that declares it, hands the request
to that program's stdin, and returns what comes back.

```
  console ──JSON lines──▶ fossh-agent ──┬─▶ telemetry     (built in)
                                        ├─▶ integrations  (built in)
                                        └─▶ yours         (your program)
```

The protocol your module speaks is the same one the console speaks to
the agent, so a module and a client are written the same way.

## The manifest

Dropped into one of these, later overriding earlier by namespace:

| Directory | For |
|---|---|
| `/usr/share/fossh/modules` | Shipped by a package |
| `/etc/fossh/modules.d` | Added by whoever administers the machine |
| `$XDG_CONFIG_HOME/fossh/modules.d` | Added by whoever runs the console |

```toml
namespace    = "backup"                    # required; [a-z][a-z0-9_]*, max 32
name         = "Backups"                   # required; shown in the console
description  = "Snapshot and restore."     # optional
exec         = "/usr/libexec/fossh-backup" # required; must be ABSOLUTE
args         = ["--serve"]                 # optional
icon         = "empty"                     # optional
timeout_secs = 30                          # optional; 1..300, default 30
```

A manifest that fails validation is skipped and reported — one bad file
does not take away every other module on the system. Check yours with:

```
$ echo '{"id":1,"method":"modules.list"}' | fossh-agent
```

Your module appears in `modules`, or the reason it did not appears in
`problems`.

## The protocol

**In**, one JSON object on one line:

```json
{"id": 7, "method": "backup.run", "params": {"target": "daily"}}
```

**Out**, one JSON object on one line — success:

```json
{"id": 7, "ok": true, "result": {"snapshot": "2026-08-15T18:00Z"}}
```

or failure:

```json
{"id": 7, "ok": false, "error": {"code": "unavailable", "message": "the volume is not mounted"}}
```

Echo the `id` you were given. Use one of these codes; anything else
becomes `internal`:

| Code | Meaning |
|---|---|
| `bad_request` | The caller's fault. Retrying unchanged will not help. |
| `not_found` | The thing named does not exist here. |
| `unavailable` | A state, not a fault — retry may work later. |
| `denied` | Something checked and refused. |
| `conflict` | Would clobber or duplicate existing state. |
| `internal` | Your module's own fault. |

Write your diagnostics to **stderr**. Stdout is the protocol; anything
else on it is a framing error. Stderr reaches the journal and is never
parsed.

## What you get, and what you do not

Your module is started fresh for each call and gets:

```
PATH=/usr/bin:/bin
FOSSH_MODULE_NAMESPACE=<your namespace>
LC_ALL=C.UTF-8
```

and nothing else. Not the agent's environment, not its file
descriptors, not its memory. `env_clear()` is called before those three
are set.

You are bounded by your manifest's `timeout_secs`, and your reply is
capped at 1 MiB. Exceed either and the call fails; your process is
killed and reaped.

## Why your module is a process and not a plugin

Because the agent holds every API key on the install, the setup token,
and a private key at the moment it is generated. Code loaded into that
process would get all of it.

A module ecosystem is also a supply chain. One popular module with one
bad release would be a credential-exfiltration incident across every
install that had it, and this project has no revocation mechanism for
that and does not intend to build one.

Your module in its own process starts with nothing and receives only
what was addressed to it. That is a real boundary rather than a
documented intention, and it costs one `fork`. If your module needs a
credential, ask the operator for it and store it yourself.

The same reasoning produced [provider definitions](packaging/providers/)
as data rather than code — see `DECISIONS.md`, ADR-0066.

## What a module cannot do

- **Claim a built-in namespace.** `agent`, `telemetry`, `integrations`,
  `providers`, `setup`, `operator`, `watchdog`, `modules`, `selfheal`.
  A manifest claiming one is rejected when it loads, not when it is
  called — by call time it is installed and the operator believes it
  works.
- **Run from a relative path.** `exec` must be absolute, so which
  program runs is not decided by whatever `PATH` the agent inherited.
- **Run unbounded**, or reply unbounded.
- **Write to the agent's stdout.** Your reply is parsed and re-emitted
  by the agent under the id the console actually sent.

## Things worth knowing

**Be fast or be honest.** You are started per call. If your work takes
real time, return `unavailable` with a message saying what is happening
and let the caller ask again, rather than holding a request open.

**Keep your own state.** Nothing is preserved between calls.

**Do not assume a human is watching.** The console calls modules; so do
scripts.

**Say what you mean in errors.** `message` is shown to an operator
verbatim. "the volume is not mounted" is worth more than "error 3".

## Where things live

| | |
|---|---|
| The protocol's wire types | `crates/fossh-agent/src/protocol.rs` |
| Module loading and routing | `crates/fossh-agent/src/modules.rs` |
| Provider definitions (data extensions) | `crates/fossh-admin/src/providers.rs` |
| The reasoning behind all of it | `DECISIONS.md`, ADR-0061 and ADR-0066 |
