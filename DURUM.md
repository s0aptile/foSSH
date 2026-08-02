# DURUM — status

Chapter-tracking file mandated by the "Fedora Native Deployment, Watchdog & Local Admin Hardening" chapter, created before any implementation work in that chapter, per its own instructions. Updated after every sub-chapter's QA gate, not just at the end. This file describes what is actually true right now; if something below turns out to be wrong, fix the code or fix this file, not the reader's expectations.

Last updated: 2026-08-02.

## Baseline (prior session, not re-implemented here)

The core product — CGI + embedded-FFI privacy-preserving telemetry — was built end to end before this chapter started:

| Milestone | Crate(s) | State |
|---|---|---|
| M1 | `fossh-core` | Done. Pure logic: validation, path/UA sanitization, HLL, histograms, config. 89 tests. |
| M2 | `fossh-store` | Done. SQLite storage, interning, rollups, retention, S8 file-permission enforcement. 42 tests. |
| M3 | `fossh-ingest`, `fossh-cgi` | Done. Auth, rate limiting, salt rotation, spool, CGI handler. 70 + 13 tests. |
| M4 | `fossh-cli` | Done. `init`/`site`/`query`/`maintain`/`export`/`doctor`. 20 tests. |
| M5 | `fossh-ffi` | Done. C ABI, `cbindgen` header, Miri-clean on the two pointer-touching functions, 32 tests in its own workspace. |
| M6 | `bindings/{go,php,ruby}` | Partial — see below. Paused to start this chapter; not abandoned. |

267 Rust tests passing across the two workspaces as of the last full run, zero clippy warnings, zero `rustfmt` diffs. Verified against real compiled binaries (CLI, a simulated CGI cycle, an independently-compiled C program linking `libfossh.so`), not just `cargo test`.

**M6 detail:** Go binding (`bindings/go`) written — cgo wrapper + `nofossh` no-op build tag + integration test — but never compiled; no Go toolchain in this environment. PHP binding: `composer.json` and `src/Client.php` (hand-maintained `FFI::cdef()` string, CGI-subprocess fallback, documented no-op if neither is available) done; Laravel/Symfony snippets, the runnable example, and Ruby's binding were not yet written when this chapter's instructions arrived. `docs/INTEGRATION-{go,php,ruby}.md` not yet written.

**Repository moved** from `/home/REDACTED/fossh` to `/home/REDACTED/Belgeler/fossh-project` at the start of this chapter (plain `mv`, git history intact, nothing recommitted or rewritten).

## This chapter — sub-chapter status

Status values: **not started**, **in progress**, **written, unverified** (code exists but couldn't be built/run here — toolchain gap, noted), **QA-gate passed** (implemented + adversarial subagent review completed + fixes applied), **blocked**.

| § | Sub-chapter | Status | Notes |
|---|---|---|---|
| 3.1 | glibc gatekeeping | not started | |
| 3.2 | Native CGI hardening (privilege drop, systemd, SELinux) | not started | `checkmodule`/`semodule_package` present — SELinux module can actually be compiled and loaded here, not just drafted. |
| 3.3 | OCaml watchdog | not started | **Blocked on toolchain**: no `ocaml`/`opam`/`dune` installed, and installing needs `sudo dnf install ocaml opam dune`. Per ADR-0023 (never handle the user's password in a command), that command is surfaced for the user to run, not executed here. Source will be written regardless and marked unverified until compiled. |
| 3.4 | QUIC IPC (quiche via ctypes) | not started | Same OCaml-toolchain blocker as 3.3. `quiche`'s Rust/C side can be built independently of OCaml being present. |
| 3.5 | Privilege separation enforcement | not started | Creating the real `fossh-svc`/`fossh-watchdog` system users needs `useradd`, i.e. root — same password constraint as above; filesystem-permission tests can still run against simulated ownership where root isn't required, full end-to-end needs the user's `dnf install`/setup. |
| 3.6 | Tamper detection | not started | Depends on the shared Rust crypto crate from 3.3's design. |
| 3.7 | CGI input trust boundary + fuzzing | not started | `cargo-fuzz` install kicked off in background at chapter start. |
| 3.8 | Data-at-rest encryption | not started | |
| 3.9 | Local TUI admin console | not started | `ratatui` confirmed to build cleanly in this environment (test compile succeeded, network to crates.io works). |
| 3.10 | Supply chain & build hardening | not started | `cargo-audit`, `cargo-deny`, `cargo-fuzz` installs kicked off in background at chapter start. |
| 3.11 | RPM packaging & setup wizard | not started | `rpmbuild` (RPM 6.0.2) present locally — the `.spec` can actually be built and lint-checked here, not just drafted. |

## Locked decisions (§2) — acknowledged, not re-litigated

Restated here only so a reader of this file doesn't have to cross-reference the chapter doc to know what's already settled: challenge-response auth gate with session tokens (§2.1); OCaml binds to `quiche` via `ctypes` rather than a pure-OCaml QUIC stack (§2.2); `fossh-watchdog`/`fossh-svc` as two separate system users (§2.3); glibc floor (candidate 2.17), dynamically linked, hard-refuse below floor — musl is no longer the target for this deployment tier (§2.5, supersedes the original spec's musl-first framing for this tier only — CGI/FFI deployment shapes elsewhere are unaffected); per-install watchdog keypair, pinned on both sides, Unix-socket bootstrap handoff (§2.4); one-time setup token, plaintext written once to a fixed path, only its hash stored, burned atomically on success (§2.6).

## Environment facts (this machine, recorded so decisions above aren't second-guessed later)

- Fedora Linux 44 (COSMIC). `dnf`, `rpmbuild` (6.0.2), `semodule`, `checkmodule`, `gcc`, `pkg-config` present. `ocaml`, `opam`, `selinux-policy` (the devel/source package) not present.
- Rust: `rustup` with `stable` (active) and `nightly` toolchains both already installed; `cargo`/`rustc` 1.97.1. `~/.cargo/bin` is not on `$PATH` in non-interactive shells in this environment — every command in this chapter that needs cargo/rustc explicitly prepends it.
- Network egress from `cargo`/`rustc` works (verified with a real `crates.io` dependency fetch, `ratatui` and its full tree). A bare `curl` to `crates.io` gets an HTTP 403 from its WAF (user-agent based, unrelated to `cargo`'s own client) — not a sign network is actually blocked, just not the way to test it.
- No passwordless `sudo` configured (`sudo -n true` fails). Per ADR-0023, the password given at the start of the original session is never placed in a command; where root is genuinely required, the exact command is surfaced here and in-chat for the user to run themselves.

## Retrospectives

(Appended one entry per sub-chapter as its QA gate closes.)
