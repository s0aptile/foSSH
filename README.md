# foSSH

Privacy-preserving, embeddable telemetry. Self-hosted site analytics without sending your visitors' data to a third party.

**Status: open alpha (`0.1.0-alpha.1`).** Working, tested, not yet exhaustively hardened everywhere — see `DURUM.md` for exactly what's done versus in progress in the current development chapter, and `DECISIONS.md` for the reasoning behind every non-obvious choice made along the way.

## Why this exists

The usual way to get basic site analytics is a hosted service that sees every visitor's traffic in order to show you a dashboard about them — Google Analytics being the largest example, but the shape of the trade is the same across most hosted options. foSSH doesn't make that trade: it runs on infrastructure you control, uses k-anonymity and rotating salted hashes instead of raw visitor identifiers, and has no central service to correlate visitors across sites in the first place, because there isn't one. See `RULES.md` for the full positioning, including why this doesn't require ripping out anything else you're already running (GA/GTM included).

## Deployment shapes

- **CGI** — `fossh-cgi`, a single static-leaning binary speaking RFC 3875 CGI. Works under Apache `mod_cgi`, or nginx via `fcgiwrap`.
- **Embedded (FFI)** — `libfossh`, a C ABI (`cdylib`/`staticlib`) linked directly into Go, PHP, Ruby, or anything else that can call a C function. No process, no socket, no open port. See `bindings/`.
- **Shared hosting** — no shell, no compiled extensions available? The PHP binding's HTTP-remote transport talks to a foSSH instance running elsewhere over plain HTTPS. See `docs/INTEGRATION-php.md`.
- **Fedora-native** — `sudo dnf install fossh` (in progress — see `DURUM.md`'s current chapter): an OCaml watchdog, hardened systemd units, SELinux confinement, and a local TUI admin console/setup wizard (`fossh-tui`).

## Quick start (building from source)

```
cargo build --release --workspace
./target/release/fossh init
./target/release/fossh site create my-site --allow pageview,signup
```

That last command prints a write key once — it's the credential every binding/transport uses to authenticate. See `docs/` for the integration guide matching how you're actually deploying (`INTEGRATION-php.md`, `DEPLOY-nginx-cloudflare-tunnel.md`, and more as they land).

## Privacy and security

`THREAT_MODEL.md` and `PRIVACY.md` cover the invariants this project holds itself to (k-anonymity thresholds, salted visitor hashing, no cross-site correlation, no `Set-Cookie`, zero outbound network access from the ingest path) once written — tracked in `DURUM.md`. In the meantime, `DECISIONS.md`'s ADR log is the authoritative record of what's actually implemented and why.

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option.

## Funding

foSSH accepts Monero donations:

```
87NdV4EUcpQWsBR77L4PdCcWZjxhxcy91YGH1hJCdeXU7ERZrwwRZYT843gCojF7wsWfTUm8zH83BRNA7DTLdh9xC8pxnmZ
```
