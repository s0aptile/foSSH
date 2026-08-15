# Retired releases

Every release before `0.2.0_oa` is retired. Do not install one, do not
build from one, and do not use one as a reference for how foSSH is
meant to work.

This file exists because "superseded" and "should not be used" are
different claims, and the 0.1.x line is the second one. What follows is
what was actually wrong with it, in enough detail to judge for
yourself.

| Release | Status | Why |
|---|---|---|
| `0.1.0_oa` | **Retired — do not use** | Pre-dates every item below. |
| `0.1.1_oa` | **Retired — do not use** | As above. |
| `0.1.2_oa` | **Retired — do not use** | As above. |
| `0.1.3_oa` | **Retired — do not use** | The last of the line, and the one carrying the defects in "What was actually broken" below. |
| `0.2.0_oa` | Current | This one. |

The final state of the retired line is preserved two ways, so the
history is auditable: the git tag `v0.1.3_oa-retired`, and a source
archive of that exact tree under `graveyard/`. Both are records, not
supported artifacts — see `graveyard/README.md`.

## What was actually broken

These are defects found by testing the 0.1.3 tree, not a general
disclaimer. Each was live in every published 0.1.x artifact.

**The watchdog could not start outside a systemd unit, and said
something else when it failed.** Supervision unconditionally handed the
supervised child off to the `fossh-svc` account via `setpriv`, which
needs `CAP_SETUID` and therefore root. Run any other way, every spawn
died instantly with exit 127, the restart-storm guard tripped after
about a second, and the **entire watchdog process exited** — taking the
operator-auth gate and the QUIC command server down with it. Anything
mid-handshake at that moment saw `Broken pipe`, which describes a
symptom four layers removed from the cause. Fixed in 0.2.0 by gating
the privilege drop on the effective uid, refusing to start with an
explicit message when it cannot be done, and adding exit code 9 for
that case.

**Three cross-language interop tests had been failing, while the
project's own status file recorded them as passing.** Two in
`fossh-tui` failed for the reason above and sent the watchdog's stderr
to `/dev/null`, so the real cause was invisible. A third
(`fossh-admin`'s `bootstrap_interop`) never set `LD_LIBRARY_PATH`, so
the watchdog binary died in the dynamic linker before `main` ran. These
are exactly the tests that exist to catch Rust↔OCaml protocol drift,
which means the drift they guard against was unguarded for the whole
0.1.x line.

**CI had, on the evidence, never once run.** `.github/workflows/ci.yml`
contained a YAML syntax error — an unquoted `: ` inside a `name:` value,
ambiguous with a nested mapping under the YAML spec — that predates the
0.1.x line entirely. Every claim of the form "this is checked in CI"
made in 0.1.x documentation should be read as unchecked.

**Shipped packages carried the build machine's identity.** The RPM and
SRPM had the real build host's username and hostname baked into package
metadata by `rpmbuild`'s own `%_topdir`/`%_buildhost` defaults. Fixed
late in 0.1.3 and automated in 0.2.0, but earlier artifacts still carry
it.

**The setup wizard was not connected to the thing it claimed to
drive.** Until very late in 0.1.3, `wizard.rs` was standalone — it
generated its own token and held its own hash rather than speaking the
watchdog's real `SETUP` protocol. A wizard that appears to complete
enrollment without the watchdog having enrolled anything is worse than
one that is absent.

## What changed in 0.2.0, structurally

Not a bug list — the shape of the product is different.

- **The terminal console is gone.** `fossh-tui` has been replaced by
  `fossh-agent`, a headless JSON-lines bridge, and `fossh-console`, a
  GTK4/libadwaita desktop application. The protocol clients that were
  inside the TUI were kept exactly as they were; only the terminal
  layer was removed.
- **A web dashboard is explicitly not the plan.** Administration is a
  native application. `fossh.org` is a website about foSSH, not an
  interface to it.
- **External services are API-key based.** An operator can add an HTTP
  endpoint with a credential; keys are sealed at rest and never
  returned to the interface.
- **Self-healing exists**, as deterministic rules with an optional,
  capability-gated local model that may only annotate them.

## If you are running 0.1.x

There is no in-place upgrade path and there is deliberately no
migration tool, because 0.1.x was an open alpha and its on-disk state
was never promised to be stable. Read `docs/UPGRADING-0.1-to-0.2.md`
before doing anything; the short version is that your event data
carries over and your admin surface does not.
