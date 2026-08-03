# foSSH

Privacy-preserving, embeddable telemetry. Light. Small. Compact.

**OPEN ALPHA (0.1.0-alpha.1).** Alpha means the *interfaces* are unstable. It does not mean the *invariants* are.

## What it is

A single binary that speaks CGI, plus a C-ABI shared library you link straight into your own process — Go, PHP, Ruby, C, or anything else that can call a C function. No process to run, no socket to open, no port to expose: the embedded shape links in and stays there.

## What it will never do

- No cross-site or cross-app identity. Ever.
- No cookies, no `localStorage`, no `ETag` tricks, no cache-based identifiers.
- No device fingerprinting: no canvas, no font enumeration, no screen-dimension entropy stacking, no TLS/JA3 fingerprints.
- No raw IP addresses at rest. Not even "temporarily", not even in logs.
- No user-agent strings at rest (parsed to coarse buckets, then discarded).
- No free-text fields from end users. Event names are allowlisted by the embedder.
- No session recording, no heatmaps, no keystrokes, no mouse paths.
- No third-party egress. foSSH never phones home to anyone, including its own authors.
- No JavaScript SDK in v1. The pixel/beacon endpoint exists, but the primary integration is server-side.
- No dashboard in v1. A read API and a `fossh query` CLI ship; UI is a separate project.

## 60-second quickstart

```
sha256sum -c SHA256SUMS            # verify the checksum first (the file shipped alongside this zip on the download page)
unzip fossh-oa.zip
cd fossh/dist
./fossh init
./fossh site create my-site --allow pageview,signup
```

Point your webserver's CGI config at `fossh-cgi` (see `docs/DEPLOY-*.md` inside the repo tree for exact blocks), then send one request to `/e.gif?name=pageview` and check it with `fossh query`.

## Deployment shapes

| Shape | What it is | Fits |
|---|---|---|
| CGI | `fossh-cgi`, RFC 3875 | Apache `mod_cgi`, nginx via `fcgiwrap` |
| FastCGI | `fossh-fcgi`, persistent, direct-to-SQLite | Higher-throughput deployments — one process, a Unix socket, its own retention/vacuum maintenance instead of cron |
| Embedded (FFI) | `libfossh` — `cdylib`/`staticlib` | Go, PHP, Ruby, C, anything with a C ABI — no process, no socket, no open port |
| Shared hosting | PHP binding's HTTP-remote transport | No shell, no compiled extensions available — plain HTTPS to a foSSH instance you run elsewhere |
| Fedora-native | `dnf install fossh` (in progress) | Self-hosted Fedora Server, with a watchdog, hardened systemd units, SELinux confinement, and a local TUI setup wizard |

## Where the real docs are

Inside `fossh/`: `README.md` (repository overview), `PRIVACY.md` (paste-able privacy page), `THREAT_MODEL.md`, `docs/INTEGRATION-*.md` (per language), `docs/DEPLOY-*.md` (per webserver, `docs/preview/` for tiers not yet through adversarial review), `DECISIONS.md` (every non-obvious choice, with the reason), `dev/DURUM.md` (current development status).

## Sizes and performance, as actually built

Measured against this release's own build, glibc `x86_64-unknown-linux-gnu` (the musl target's C toolchain is not available in this build environment — see `DECISIONS.md`; a musl build is expected to be somewhat larger, not smaller, so these numbers are not the best case):

- `fossh-cgi` (stripped release binary): 536 KB
- `fossh` (CLI, stripped release binary): 1.8 MB
- `fossh-tui` (stripped release binary): 1.6 MB
- `libfossh.so` (stripped release cdylib): 1.8 MB
- `fossh-cgi`'s direct third-party dependencies: 2 (`blake3`, `nix`) — plus this project's own internal crates, which aren't external surface
- `GET /healthz` round trip, cold: ~1 ms

## License

MIT. See `tos.md` for the full terms and disclaimer.

## Author

$0aptile — github.com/s0aptile
