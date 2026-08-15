# foSSH

A modular platform for self-hosted, privacy-preserving measurement. Its flagship module is site analytics — telemetry without sending your visitors' data to a third party — and that module is why most people install it.

The crates below are factored so telemetry is *a* module rather than the whole system; `MODULES.md` documents how to write another. Stated plainly: telemetry is the only module of substance today, and the module interface is not stable yet.

**Status: open alpha (`0.0.2.2`).** Every release before this one is retired — see `RETIREMENT.md` for what was actually wrong with the 0.1.x line, and `docs/UPGRADING-from-0.1.md` if you are running one.

**Previously:** Working, tested, not yet exhaustively hardened everywhere — see `dev/DURUM.md` for exactly what's done versus in progress in the current development chapter, and `DECISIONS.md` for the reasoning behind every non-obvious choice made along the way.

## Why this exists

The usual way to get basic site analytics is a hosted service that sees every visitor's traffic in order to show you a dashboard about them — Google Analytics being the largest example, but the shape of the trade is the same across most hosted options. foSSH doesn't make that trade: it runs on infrastructure you control, uses k-anonymity and rotating salted hashes instead of raw visitor identifiers, and has no central service to correlate visitors across sites in the first place, because there isn't one. See `RULES.md` for the full positioning, including why this doesn't require ripping out anything else you're already running (GA/GTM included).

## What it will never do

- No cross-site or cross-app identity. Ever.
- No cookies, no `localStorage`, no `ETag` tricks, no cache-based identifiers.
- No device fingerprinting: no canvas, no font enumeration, no screen-dimension entropy stacking, no TLS/JA3 fingerprints.
- No raw IP addresses at rest. Not even temporarily, not even in logs.
- No user-agent strings at rest (parsed to coarse buckets, then discarded).
- No free-text fields from end users. Event names are allowlisted by the embedder.
- No session recording, no heatmaps, no keystrokes, no mouse paths.
- foSSH never phones home to anyone, including its own authors. There is no telemetry about your telemetry.
- No JavaScript SDK in v1. The pixel/beacon endpoint exists, but the primary integration is server-side.
- No hosted dashboard, and no web dashboard at all. Administration is `fossh-console`, a desktop application that runs on your own machine and talks to a local helper over a pipe — see "Administration" below. A read API and a `fossh query` CLI ship alongside it.
- No third-party egress **from the ingest path**. This is now stated precisely rather than broadly: `fossh-cgi`, `fossh-fcgi` and `libfossh` cannot make an outbound connection, enforced by which crates are in their dependency tree rather than by configuration (`cargo tree -p fossh-cgi | grep fossh-agent` finds nothing). An integration you configure yourself is operator-initiated, never on the ingest path, and carries no visitor data.

`THREAT_MODEL.md` covers the full reasoning behind each of these, including what's explicitly *not* defended against.

## Deployment shapes

- **CGI** — `fossh-cgi`, a single static-leaning binary speaking RFC 3875 CGI. Works under Apache `mod_cgi`, or nginx via `fcgiwrap`.
- **FastCGI** — `fossh-fcgi`, a persistent process speaking FastCGI directly over a Unix socket, for higher-throughput deployments than a fresh process per request. Writes straight to SQLite in batches instead of spooling, and runs its own retention/vacuum maintenance instead of relying on cron. See `packaging/systemd/fossh-fcgi.service`.
- **Embedded (FFI)** — `libfossh`, a C ABI (`cdylib`/`staticlib`) linked directly into Go, PHP, Ruby, or anything else that can call a C function. No process, no socket, no open port. See `bindings/`.
- **Shared hosting** — no shell, no compiled extensions available? The PHP binding's HTTP-remote transport talks to a foSSH instance running elsewhere over plain HTTPS. See `docs/INTEGRATION-php.md`.
- **Fedora-native** — `sudo dnf install fossh` (in progress — see `dev/DURUM.md`'s current chapter): the portable core (`fossh-cgi`/`fossh-fcgi`/`fossh` CLI/`fossh-agent`), hardened systemd units, and an SELinux policy module confining `fossh-cgi`/`fossh-fcgi`, plus an optional `fossh-watchdog` subpackage — the OCaml watchdog, tamper detection, and the operator-auth enrollment gate the console's setup flow drives.
- **RHEL family (RHEL, Rocky, Alma) via EPEL** — as of `packaging/rpm/fossh.spec`'s subpackage split, the same portable core (`fossh-cgi`/`fossh-fcgi`/`fossh` CLI/`fossh-agent`/SELinux module) is a *separate*, everywhere-buildable package from `fossh-watchdog` — `dnf copr enable s0aptile/fossh epel-9-x86_64` (or `epel-10-x86_64`) once a build actually succeeds there. No `fossh-watchdog` on EPEL/RHEL, ever, as things stand: it needs `ocaml-ctypes-devel`, not packaged for EPEL. That means no supervised restart-on-crash, no tamper detection, and no operator-auth gate — `fossh-fcgi` runs as a plain, unsupervised systemd service, and the console's Overview and Setup pages report an honest "watchdog unreachable" rather than doing anything (its Telemetry page, reading straight from the SQLite store, is unaffected). Not installable from a repository yet. The link failure that blocked every chroot including Fedora's own is fixed as of 0.0.2.2 — a full RPM build now succeeds locally, all four packages — but no Copr build has been attempted since, so there is still nothing published to install. See `docs/PACKAGING-copr.md` for what is confirmed fixed and what remains.
- **Fedora Atomic (Silverblue, Kinoite, CoreOS)** — `rpm-ostree install fossh` plus a reboot, once the Copr repo is added the ostree-appropriate way. See `docs/DEPLOY-atomic.md`.

## Quick start — pick your path

**On shared hosting (cPanel, FTP/File Manager only, no shell)?** Skip everything below. Grab [`docs/fossh-config.php`](docs/fossh-config.php), fill in the two blanks (a write key from someone/somewhere already running foSSH, and its address), upload it, add one `require_once` line to your site. No build, no Composer, no server access needed — the file's own header comment walks through the three steps. That's the whole install.

**Self-hosting foSSH itself** — your own server, one install that can hold as many sites as you want (each `site create` below is a separate site with its own write key and its own numbers; nothing about the install is per-site):

```
cargo build --release --workspace
./target/release/fossh init --dir ./data
./target/release/fossh site create my-site --allow pageview,signup
```

`--dir` is required here unless you're running as root: the default (`/var/lib/fossh`) is a system path a normal user can't write to, and `site create` afterward picks up `./data` automatically from the `./fossh.toml` that `init` just wrote. That last command prints a write key once — it's the credential every binding/transport uses to authenticate, including any shared-hosting sites (above) that point at this install as their endpoint. Reachable from the public internet with zero inbound ports opened (Cloudflare Tunnel) is the documented way to expose it: `docs/preview/DEPLOY-nginx-cloudflare-tunnel.md`. See `docs/` for the integration guide matching how you're actually deploying (`INTEGRATION-php.md`, `DEPLOY-apache.md`, and more as they land).

## Administration

`fossh-console` is a GTK4/libadwaita desktop application: today's
figures across every site, real k-anonymised queries against the rollup
store, management of external services you have added, and the
first-run operator enrollment flow.

```
sudo dnf install fossh-console
fossh-console
```

**That command does not work yet**, and will not until the packages are
published — foSSH is not in Fedora, and the Copr repository has no
successful build to install. Today the console is run from a source
build, alongside the rest: see "Quick start" above for the workspace
build, then
`python3 -m fossh_console` from `gui/`. `docs/PACKAGING-copr.md` tracks
what is still blocking the packages, and this line changes the day that
is finished rather than before it.

It never listens on a socket. Everything it shows comes from
`fossh-agent`, a helper it spawns over a pipe, and no credential
outlives the call that carries it — an API key you add is sealed on
disk immediately and is never sent back to the window, which shows at
most its last four characters.

This replaces `fossh-tui`, the terminal console shipped up to 0.1.3.
The protocol clients that lived inside it were kept exactly as they
were; only the terminal layer was removed. See `DECISIONS.md`'s
ADR-0061.

## External services

An integration is an endpoint you control plus an API key you supply.
Keys are sealed at rest under this install's own data key, never
written to a log, and never returned to the console. Plain `http://` is
refused for anything but a loopback address.

Six provider templates ship for common services (a generic webhook,
AWS API Gateway, Datadog, Honeycomb, Axiom, Better Stack) and more can
be added as TOML files in `/etc/fossh/providers.d` — declaratively,
not as loadable code. `DECISIONS.md`'s ADR-0066 explains why that
distinction is deliberate in a process that holds every credential on
the install.

## Self-healing

`fossh doctor` runs deterministic rules over the install's real state —
file permissions, the k-anonymity setting, a leftover setup token, a
missing GeoIP database, an unreachable watchdog — and reports each with
a remedy. Automatic remedies are restricted to permission tightening;
anything that deletes, rewrites or relaxes a setting is printed for you
to run.

Optionally, `fossh-selfheal` adds a small local language model that can
attach a plain-language explanation to a finding — and only that. It
cannot create a finding, change a severity, alter a remedy, or cause
anything to run.

It runs entirely on the CPU, on your own machine, and nothing it is
shown or produces leaves that machine. It is off unless the hardware
clears a floor — 4 physical cores with AVX2 (an Intel Core i7-6700K or
AMD Ryzen 5 1500X and up), 8 GiB of RAM, 32 GiB of storage — and then
passes a timed check for latency and throughput. See
`docs/SELF-HEALING.md`.

## Privacy and security

`THREAT_MODEL.md` and `PRIVACY.md` cover the invariants this project holds itself to (k-anonymity thresholds, salted visitor hashing, no cross-site correlation, no `Set-Cookie`, zero outbound network access from the ingest path), including what's explicitly *not* defended against and this release's alpha caveats (no third-party audit; fuzzing has been run as a real long unattended pass — 933.9M executions across 5 targets, zero crashes — and a short smoke run of the same 5 targets is now wired into CI on every push/PR). `DECISIONS.md`'s ADR log is the authoritative record of what's actually implemented and why.

### What a low-traffic site's numbers will look like

`k_anonymity` in `fossh.toml` (default `5`) is a floor on every reported group, not just a knob for busy sites: any `fossh query --group-by ...` breakdown where a particular path/country/browser/etc. had fewer than `k` estimated unique visitors gets folded into a single `(other)` row instead of being shown on its own (P6, enforced once, in `fossh-store`'s query engine, so no read path can bypass it — see `THREAT_MODEL.md`'s "curious operator" entry). For a site with only a handful of visitors a day, this is the normal case, not a malfunction: a blog getting 3 unique visitors on a given day will see every `--group-by path` breakdown for that day collapse into one `(other)` row, because no individual page cleared the k=5 threshold on its own. The total `hits`/`uniques` numbers (querying with no `--group-by` at all) are unaffected by this — folding a single already-aggregate total doesn't change its value, only per-group breakdowns can disappear this way. `fossh query` prints a note to stderr when a result is entirely the `(other)` fold, so this doesn't read as a silent empty result. Ways to get real per-group numbers back: widen `--from`/`--to` to accumulate more days of traffic before grouping, group by a coarser dimension (`country` folds less than `path` on the same traffic), or lower `k_anonymity` — which is a real anonymity/granularity tradeoff to make deliberately, not a default to change to make a number look less empty.

### Country resolution (GeoIP)

`country_db` in `fossh.toml` (or `FOSSH_COUNTRY_DB` for `fossh-cgi`, which reads environment variables directly rather than the config file — see that binary's own `main.rs`) controls where per-event country codes come from. It takes one of three shapes: `"none"` (the default a fresh `fossh init` writes — no lookup happens at all, every event's country is the `"ZZ"` unknown sentinel, and nothing under this section applies), a filesystem path to an MMDB-format IP-to-country database, or `"builtin"` (reserved for a future package-bundled database; as of this release it behaves identically to `"none"`, since no such database is bundled — see `NOTICE`).

Given a path, resolution reads exactly one already-resolved client IP (the same value P2's visitor hashing uses — see `fossh_ingest::forwarded`'s trust-boundary handling of `X-Forwarded-For`) through that MMDB file and keeps only the two-letter ISO-3166-1 country code; the address itself never touches disk, a log line, or an error message anywhere on this path (`fossh-ingest/src/geoip.rs` is the whole of it — small on purpose, so it's auditable in one read). A missing, unreadable, or corrupt database file, or an address with no entry, both resolve to `"ZZ"` silently — country resolution is additive, never a reason ingestion fails.

No database ships with foSSH itself. This project's own guidance is db-ip.com's free "IP to Country Lite" database — MMDB format (the same binary format MaxMind's GeoLite2 uses; db-ip.com is an unrelated, no-account-required provider), licensed CC BY 4.0, updated monthly, downloadable without registration from `https://db-ip.com/db/download/ip-to-country-lite`. Point `country_db` at wherever you save the `.mmdb` file after downloading and decompressing it; nothing else needs to change. Using it (or any other MaxMind-DB-format database) requires no special foSSH configuration beyond that one line — see `NOTICE` for the attribution its license requires and this project's own reproduction of it.

## Documentation index

This is a lot of root-level files — most of them sit here because the project's own legal/authorship addendum (§19 of the original spec) requires it, the same way `LICENSE`/`NOTICE`/`SECURITY.md` sit at the root of most real-world repositories for tooling (GitHub included) to find them. One map through all of it:

| File | What it's for |
|---|---|
| `readme.md` | The *release* readme (zip root) — shorter, quickstart-focused. Distinct from this file. |
| `PRIVACY.md` | Paste-able privacy-page text. |
| `THREAT_MODEL.md` | Assets, adversaries, what's defended against and what isn't, alpha caveats. |
| `tos.md` | Terms of use and disclaimer — the legal posture, not a contract for services. |
| `SECURITY.md` | How to report a vulnerability. |
| `NOTICE` | Third-party dependency licenses, generated, not hand-maintained. |
| `AUTHORS`, `LICENSE` | Exactly what they say. |
| `RULES.md` | Naming, tone, the public/private boundary, platform support, positioning. |
| `DECISIONS.md` | The ADR log — every non-obvious choice, and why. |
| `MODULES.md` | How to write a module: the protocol, the manifest, and why a module is a process rather than a plugin. |
| `RETIREMENT.md` | Which releases are retired, and what was actually wrong with them. |
| `docs/SELF-HEALING.md` | The deterministic rules, and the fence around the optional model. |
| `dev/` | How this project is actually being built, right now — chapter status (`dev/DURUM.md`), retrospectives. Not end-user documentation; read `docs/` for that. |
| `docs/` | Per-language and per-webserver integration guides. |
| `docs/preview/` | Deployment tiers documented ahead of the adversarial-review pass the rest of this project's deployment surfaces go through — the intended shape, not a reviewed, supported path yet. |
| `PUBLISH.md` | Gitignored, not shipped — the author's own publishing copy-paste sheet. |
| `private-onlyauthor/` | Gitignored, not shipped — anything identifying, or any private note, for the author's eyes only. |

## License

Licensed under [MIT](LICENSE).

## Funding

foSSH accepts donations on:

- **Solana (SPL):** `J7wgrgySAVvWmreXiM51ig3rqY1vNnpdpvqZsHZLPfwD`
- **Neon (Neon EVM):** `0xEde8Dd4413b667269e3Df902C49532C2212475AF`
- **Monero** — accepted, but a transfer is harder to reconcile against a donation than the two above, so it is the last resort rather than the first choice: `87NdV4EUcpQWsBR77L4PdCcWZjxhxcy91YGH1hJCdeXU7ERZrwwRZYT843gCojF7wsWfTUm8zH83BRNA7DTLdh9xC8pxnmZ`
