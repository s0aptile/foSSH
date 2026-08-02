# foSSH

Privacy-preserving, embeddable telemetry. Self-hosted site analytics without sending your visitors' data to a third party.

**Status: open alpha (`0.1.0-alpha.1`).** Working, tested, not yet exhaustively hardened everywhere — see `dev/DURUM.md` for exactly what's done versus in progress in the current development chapter, and `DECISIONS.md` for the reasoning behind every non-obvious choice made along the way.

## Why this exists

The usual way to get basic site analytics is a hosted service that sees every visitor's traffic in order to show you a dashboard about them — Google Analytics being the largest example, but the shape of the trade is the same across most hosted options. foSSH doesn't make that trade: it runs on infrastructure you control, uses k-anonymity and rotating salted hashes instead of raw visitor identifiers, and has no central service to correlate visitors across sites in the first place, because there isn't one. See `RULES.md` for the full positioning, including why this doesn't require ripping out anything else you're already running (GA/GTM included).

## Deployment shapes

- **CGI** — `fossh-cgi`, a single static-leaning binary speaking RFC 3875 CGI. Works under Apache `mod_cgi`, or nginx via `fcgiwrap`.
- **FastCGI** — `fossh-fcgi`, a persistent process speaking FastCGI directly over a Unix socket, for higher-throughput deployments than a fresh process per request. Writes straight to SQLite in batches instead of spooling, and runs its own retention/vacuum maintenance instead of relying on cron. See `packaging/systemd/fossh-fcgi.service`.
- **Embedded (FFI)** — `libfossh`, a C ABI (`cdylib`/`staticlib`) linked directly into Go, PHP, Ruby, or anything else that can call a C function. No process, no socket, no open port. See `bindings/`.
- **Shared hosting** — no shell, no compiled extensions available? The PHP binding's HTTP-remote transport talks to a foSSH instance running elsewhere over plain HTTPS. See `docs/INTEGRATION-php.md`.
- **Fedora-native** — `sudo dnf install fossh` (in progress — see `dev/DURUM.md`'s current chapter): an OCaml watchdog, hardened systemd units, SELinux confinement, and a local TUI admin console/setup wizard (`fossh-tui`).

## Quick start (building from source)

```
cargo build --release --workspace
./target/release/fossh init
./target/release/fossh site create my-site --allow pageview,signup
```

That last command prints a write key once — it's the credential every binding/transport uses to authenticate. See `docs/` for the integration guide matching how you're actually deploying (`INTEGRATION-php.md`, `DEPLOY-apache.md`, `docs/preview/DEPLOY-nginx-cloudflare-tunnel.md`, and more as they land).

## Privacy and security

`THREAT_MODEL.md` and `PRIVACY.md` cover the invariants this project holds itself to (k-anonymity thresholds, salted visitor hashing, no cross-site correlation, no `Set-Cookie`, zero outbound network access from the ingest path), including what's explicitly *not* defended against and this release's alpha caveats (no third-party audit, no fuzzing run yet). `DECISIONS.md`'s ADR log is the authoritative record of what's actually implemented and why.

## Documentation index

This is a lot of root-level files — most of them sit here because the project's own legal/authorship addendum (§19 of the original spec) requires it, the same way `LICENSE`/`NOTICE`/`SECURITY.md` sit at the root of most real-world repositories for tooling (GitHub included) to find them. One map through all of it:

| File | What it's for |
|---|---|
| `readme.md` | The *release* readme (zip root) — shorter, quickstart-focused. Distinct from this file. |
| `PRIVACY.md` / `PRIVACY.tr.md` | Paste-able privacy-page text, in English and Turkish. |
| `README.tr.md` | Turkish translation of this file. |
| `THREAT_MODEL.md` | Assets, adversaries, what's defended against and what isn't, alpha caveats. |
| `tos.md` | Terms of use and disclaimer — the legal posture, not a contract for services. |
| `SECURITY.md` | How to report a vulnerability. |
| `NOTICE` | Third-party dependency licenses, generated, not hand-maintained. |
| `AUTHORS`, `LICENSE` | Exactly what they say. |
| `RULES.md` | Naming, tone, the public/private boundary, platform support, positioning. |
| `DECISIONS.md` | The ADR log — every non-obvious choice, and why. |
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
- **Monero** (not recommended): `87NdV4EUcpQWsBR77L4PdCcWZjxhxcy91YGH1hJCdeXU7ERZrwwRZYT843gCojF7wsWfTUm8zH83BRNA7DTLdh9xC8pxnmZ`
