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

**M6 detail:** Go binding (`bindings/go`) written — cgo wrapper + `nofossh` no-op build tag + integration test — but never compiled; no Go toolchain in this environment. PHP binding: `composer.json` and `src/Client.php` done, now with **three** transports tried in order — FFI, then HTTP-remote (bearer-token auth over plain HTTPS, for real shared hosting — see `docs/INTEGRATION-php.md`), then CGI-subprocess, then a documented no-op. Laravel/Symfony middleware snippets, the runnable example, and Ruby's binding are still not written. `docs/INTEGRATION-php.md` done (shared-hosting-focused, per the user's direct request mid-chapter); `docs/INTEGRATION-{go,ruby}.md` not yet written.

**Repository relocated** to its current path at the start of this chapter (plain `mv` within the author's own home directory, git history intact, nothing recommitted or rewritten). The absolute path itself is not repeated here — see §19.4.12's identity-hygiene gate on real home-directory paths.

## This chapter — sub-chapter status

Status values: **not started**, **in progress**, **written, unverified** (code exists but couldn't be built/run here — toolchain gap, noted), **QA-gate passed** (implemented + adversarial subagent review completed + fixes applied), **blocked**.

| § | Sub-chapter | Status | Notes |
|---|---|---|---|
| 3.1 | glibc gatekeeping | QA-gate passed | Implemented, not yet load-bearing anywhere (see retrospective) — no systemd unit exists yet to call `glibc-check` automatically. |
| 3.2 | Native CGI hardening (privilege drop, systemd, SELinux) | QA-gate passed | Privilege-drop code and systemd units held up under adversarial review with only theoretical/cosmetic nits. The SELinux module had three concrete missing-grant bugs, all fixed and re-verified to compile/package; one architectural question (which domain `fcgiwrap` actually execs from) remains open pending a live, rooted load — see retrospective. |
| 3.3 | OCaml watchdog | not started | **Blocked on toolchain**: no `ocaml`/`opam`/`dune` installed, and installing needs `sudo dnf install ocaml opam dune`. Per ADR-0023 (never handle the user's password in a command), that command is surfaced for the user to run, not executed here. Source will be written regardless and marked unverified until compiled. |
| 3.4 | QUIC IPC (quiche via ctypes) | not started | Same OCaml-toolchain blocker as 3.3. `quiche`'s Rust/C side can be built independently of OCaml being present. |
| 3.5 | Privilege separation enforcement | not started | Creating the real `fossh-svc`/`fossh-watchdog` system users needs `useradd`, i.e. root — same password constraint as above; filesystem-permission tests can still run against simulated ownership where root isn't required, full end-to-end needs the user's `dnf install`/setup. |
| 3.6 | Tamper detection | not started | Depends on the shared Rust crypto crate from 3.3's design. |
| 3.7 | CGI input trust boundary + fuzzing | not started | `cargo-fuzz` install kicked off in background at chapter start. |
| 3.8 | Data-at-rest encryption | implemented (spool only) | Spool frames sealed with ChaCha20-Poly1305 under a per-install key; the rollup SQLite database is deliberately not encrypted this pass — see ADR-0027 for the reasoning (it holds aggregates, not raw rows). |
| 3.9 | Local TUI admin console | not started | `ratatui` confirmed to build cleanly in this environment (test compile succeeded, network to crates.io works). |
| 3.10 | Supply chain & build hardening | partial | `cargo audit` and `cargo deny check` (advisories/bans/licenses/sources) both genuinely clean in **both** workspaces (`deny.toml` at the root and in `crates/fossh-ffi/`) — 242 + 72 crate dependency graphs, real runs, not configured-and-assumed. `opam` audit still blocked on the OCaml toolchain (§3.3). Stripped-release-symbol verification and a real reproducible-build (build twice, diff SHA-256) check are not done yet. |
| 3.11 | RPM packaging & setup wizard | core packaging done | `packaging/rpm/fossh.spec` builds a real, complete `fossh-0.1.0~alpha.1-1.fc44.x86_64.rpm` end to end on this box (`dist/`, gitignored) — verified via an actual full `rpmbuild -bb`, not just spec-parsing. `%post` leaves the service enabled but not started (awaiting-setup, per §3.11's own wording). Not done: `rpmlint` (not installed), and the setup wizard's full "enroll a real key" step, since that depends on the watchdog (§3.3). |

## Locked decisions (§2) — acknowledged, not re-litigated

Restated here only so a reader of this file doesn't have to cross-reference the chapter doc to know what's already settled: challenge-response auth gate with session tokens (§2.1); OCaml binds to `quiche` via `ctypes` rather than a pure-OCaml QUIC stack (§2.2); `fossh-watchdog`/`fossh-svc` as two separate system users (§2.3); glibc floor (candidate 2.17), dynamically linked, hard-refuse below floor — musl is no longer the target for this deployment tier (§2.5, supersedes the original spec's musl-first framing for this tier only — CGI/FFI deployment shapes elsewhere are unaffected); per-install watchdog keypair, pinned on both sides, Unix-socket bootstrap handoff (§2.4); one-time setup token, plaintext written once to a fixed path, only its hash stored, burned atomically on success (§2.6).

## Environment facts (this machine, recorded so decisions above aren't second-guessed later)

- Fedora Linux 44 (COSMIC). `dnf`, `rpmbuild` (6.0.2), `semodule`, `checkmodule`, `gcc`, `pkg-config` present. `ocaml`, `opam`, `selinux-policy` (the devel/source package) not present.
- Rust: `rustup` with `stable` (active) and `nightly` toolchains both already installed; `cargo`/`rustc` 1.97.1. `~/.cargo/bin` is not on `$PATH` in non-interactive shells in this environment — every command in this chapter that needs cargo/rustc explicitly prepends it.
- Network egress from `cargo`/`rustc` works (verified with a real `crates.io` dependency fetch, `ratatui` and its full tree). A bare `curl` to `crates.io` gets an HTTP 403 from its WAF (user-agent based, unrelated to `cargo`'s own client) — not a sign network is actually blocked, just not the way to test it.
- No passwordless `sudo` configured (`sudo -n true` fails). Per ADR-0023, the password given at the start of the original session is never placed in a command; where root is genuinely required, the exact command is surfaced here and in-chat for the user to run themselves.

## Retrospectives

(Appended one entry per sub-chapter as its QA gate closes.)

### §3.8 — Data-at-rest encryption

Scoped to the spool specifically, not the rollup SQLite database — see ADR-0027 for the full reasoning (the database holds k-anonymity-folded aggregates; the spool is where genuinely raw, per-visitor telemetry actually sits on disk, even if briefly). Built: `fossh_admin::data_key` (per-install key, race-safe `load_or_generate`, 5 tests including 8 real concurrent threads racing a cold-start), `fossh_ingest::crypto` (ChaCha20-Poly1305 seal/open, 7 tests covering the round trip, wrong key, tampered ciphertext, and truncation), and wiring through all three transports that touch the spool: `fossh-cgi` (loads the key once per process, after the privilege drop, before the `/healthz` fast path would ever need it), `fossh-cli maintain`, and `fossh-ffi`'s `mode = "spool"` path (`record`/`fossh_flush`) — confirmed by running `fossh-ffi`'s own `flush_drains_the_spool_in_spool_mode` test, which exercises the modified code directly, not just a unit test of the crypto primitive in isolation.

Added two integration-level tests beyond the crypto module's own unit tests: one asserts the literal on-disk spool file bytes don't contain a distinctive plaintext path/name marker (proving encryption actually happens at the file level, not just in a round-trip assertion that could pass even if encryption were accidentally a no-op), and one confirms draining with the wrong key reports every frame `Corrupt` rather than panicking or silently producing wrong data.

Full workspace (both the root and `fossh-ffi`'s separate one) still green after the change: 280 + 32 = 312 tests, clippy clean, fmt clean in both. The RPM built for §3.11 predates this change — rebuilding it to pick up the new code is a follow-up, not done as part of this entry.

### §3.1 — glibc gatekeeping

Built: `fossh_core::glibc_gate` (pure `ldd --version` parsing/comparison, 7 tests), `fossh_cli::common::detect_glibc_version` (the one I/O-performing caller both `doctor` and the new `fossh glibc-check` subcommand share), and the floor constant (2.17, per §2.5's candidate). Deliberately not wired into `fossh-cgi`'s per-request path — see ADR-0024 for the full reasoning (subprocess-per-request would tax the sub-5ms p99 budget for no benefit, since the host's glibc can't change request-to-request).

Adversarial pass caught one real, moderate-to-high-severity bug: neither call site checked `ldd`'s exit status before trusting its stdout, so a failing `ldd` (e.g. a half-broken glibc install — precisely the failure mode this check exists to catch) that still printed something version-shaped on stdout parsed as a clean pass. Confirmed empirically against the compiled binary with a shadowed fake `ldd` on `$PATH`, not just by reading the code. Fixed by collapsing both call sites onto one shared helper that checks `status.success()` first — see ADR-0024. Re-ran the adversarial repro against the fix directly; it now correctly refuses.

Also caught and fixed: a doc comment in `glibc_gate.rs` referenced an ADR that didn't exist yet (fixed by writing ADR-0024 for real, not by softening the comment) and a dangling `RULES.md` pointer in the refusal message (RULES.md has no glibc content; the message now points at DURUM.md only).

No deviation from §2.5's locked decision. One thing worth being explicit about, flagged in ADR-0024 too: the check exists but isn't automatically invoked by anything yet — that lands with §3.2's systemd unit (`ExecStartPre=`).

### §3.2 — Native CGI hardening

Built: privilege-drop (`fossh-cgi/src/privdrop.rs`, using `nix`'s safe wrappers, never touching this crate's `#![forbid(unsafe_code)]` — setgid → initgroups → setuid, then verifies the drop actually stuck by attempting to reclaim root); the SELinux module (`packaging/selinux/fossh.{te,fc}`, written from scratch in raw native TE syntax since this environment has `checkmodule`/`semodule_package` but not `selinux-policy-devel`'s M4 interface library — see the file's own header comment); and the systemd units (`packaging/systemd/fossh-fcgiwrap.{socket,service}`, `fossh.tmpfiles.conf`) with the full hardening directive set (`PrivateNetwork`, `ProtectSystem=strict`, `NoNewPrivileges`, capability/syscall restriction, etc.) plus `ExecStartPre=fossh glibc-check`.

Verified as far as this rootless environment allows: `checkmodule`/`semodule_package` both compile and package the policy module cleanly (real compile, re-run against the final file content, not just written-and-hoped); `systemd-analyze verify` parses both units cleanly (only complaining that `/usr/bin/fossh`/`/usr/sbin/fcgiwrap` aren't installed system-wide here, which is expected pre-install). Not verified here, needs root: actually loading the SELinux module (`semodule -i`) and testing real AVC enforcement against a live process; exercising the privilege-drop code's actual-root-successfully-dropped path (this session never runs as root, per ADR-0023); creating the real `fossh-svc`/`fossh-watchdog` system users the units and policy both assume exist (that's §3.5/§3.11's job). Adversarial-review subagent pass launched; retrospective will be updated with findings once it returns.

Also fixed, while working on this: the earlier preview nginx+Cloudflare-Tunnel guide (`docs/DEPLOY-nginx-cloudflare-tunnel.md`) referenced a hand-rolled socket path (`/run/fcgiwrap-fossh.sock`) that no longer matches the real shipped unit (`/run/fossh/fcgiwrap.sock`) — updated that guide to reference the real unit files directly instead of a duplicated hand-rolled copy, and added the `real_ip_header`/`set_real_ip_from` nginx config it was missing (without it, every visitor behind that guide's Cloudflare Tunnel setup would have collapsed to `127.0.0.1` as far as `fossh-cgi` could tell — cloudflared's own loopback hop to nginx, not the actual visitor).

**Adversarial review findings and fixes.** `privdrop.rs` and the systemd units held up well — the reviewer traced the setgid-before-setuid ordering, `initgroups`' full (not additive) group replacement, and the reclaim-root verification check against actual Linux/`nix`-0.29.0 semantics and found them sound, plus confirmed the hardening directives (`RestrictAddressFamilies=AF_UNIX`, `PrivateNetwork`, `ProtectSystem=strict` + `ReadWritePaths`) actually match what the code touches, cross-referenced line by line against `handler.rs`/`salt.rs`. One low-severity nit noted (the reclaim-check doesn't discriminate on errno) — not fixed, narrow enough not to be worth the complexity.

The SELinux module was a different story: the reviewer correctly pointed out that "compiles cleanly" (this project's own verification claim) gives **no assurance at all** about missing `allow` rules, since `require{}` blocks aren't resolved against a real base policy until load time — and found three concrete ones by checking this box's actual labels (`ls -Zd`) and cross-referencing actual code instead of the policy's own assumptions:

- **Missing ancestor-directory `search` grants** for `/etc` (`etc_t`), `/usr` (`usr_t`), `/var` (`var_t`), `/var/lib` (`var_lib_t`) — SELinux checks `dir:search` at every path component, so without these the dynamic linker likely can't even resolve `libc`/`ld.so.cache` and the domain can't reach its own data directory. Likely would have broken every single exec. **Fixed**: added explicit `search`/`read`/`getattr` grants for all four, plus `lib_t:dir` (the directory form of a type this module already required, previously only granted `file`/`lnk_file` access on).
- **`/dev/urandom` (`urandom_device_t`) never granted at all** — confirmed via `fossh-ingest/src/random.rs` that this is opened directly (not `getrandom(2)`) on the hot path whenever the daily salt rotates. **Fixed**: added `chr_file { read write getattr open ioctl }` on `urandom_device_t`.
- **`capability { setuid setgid }` was `require`d but never actually `allow`ed** — would have blocked `privdrop.rs` under enforcement in the one scenario it exists for (this binary genuinely exec'd as root). **Fixed**: added `allow fossh_cgi_t self:capability { setuid setgid };`.

Also addressed, not a bug but a real architectural gap the reviewer flagged and I couldn't resolve without root: the shipped systemd unit execs `fcgiwrap`, not `fossh-cgi`, directly — `fcgiwrap` itself execs `fossh-cgi` per request, and whatever domain `fcgiwrap` actually runs in (the unit sets no `SELinuxContext=`) might not be `init_t` or `httpd_t` at all; Fedora commonly lands such units in `unconfined_service_t`, in which case the transition never fires and `fossh-cgi` runs completely unconfined, silently. Added `unconfined_service_t` as a third source domain for the same transition, as a defensive best guess — but the actual answer (`ps -eZ | grep fcgiwrap` after a real `semodule -i` + service start) is still open and needs root to confirm; tracked here rather than glossed over.

While fixing the above, also trimmed genuinely unused permissions the reviewer traced through the actual ingest code (`lock`/`map` on `fossh_data_t`/`fossh_var_run_t:file` — nothing on this path uses `mmap()` or advisory locking, per ADR-0013), removed redundant `entrypoint`/`execute_no_trans` grants on the source domains' view of the executable (the check only consults the target domain's relationship, already granted separately), and corrected a stale comment claiming `fossh_data_t` represents the SQLite database — it doesn't; `fossh-cgi` never opens `fossh.db` directly, only the JSON site-cache and per-site spool/ratelimit/nonce files. Re-verified with `checkmodule`/`semodule_package` after every fix — still compiles and packages cleanly. The nginx+tunnel doc's socket-path/`real_ip` drift the reviewer also flagged had already been fixed earlier in this same session, before the review returned — confirmed no residual drift remains.

### §3.11 — RPM packaging

Wrote `packaging/rpm/fossh.spec` (no `rust2rpm`/Fedora Rust-packaging macros — this environment doesn't have that package, so `%build`/`%install` are plain `cargo build --release --workspace` + manual `install -D`, a valid if less-automated alternative) and got a **real, complete `rpmbuild -bb` to succeed** — not just `rpmspec --parse` or a source-RPM check. `~/rpmbuild/RPMS/x86_64/fossh-0.1.0~alpha.1-1.fc44.x86_64.rpm` exists, is a real ~1.5 MB package with correctly auto-detected glibc/libgcc/libm `Requires:`, correct `%pre`/`%post`/`%preun`/`%postun`/`%posttrans` scriptlet expansion (verified by reading `rpm -qp --scripts` output, not assumed) using the real `%selinux_modules_install`/`%selinux_relabel_post`/`%systemd_post` macros this system actually ships, and the right file manifest (`rpm -qlp`). Copied into `dist/` (gitignored) alongside the source RPM.

Two honest gaps, not hidden: `rpmlint` isn't installed here, so no static-lint pass beyond what `rpmbuild` itself checks; and `--nodeps` was needed for the `-bb` run because this dev box provisions its Rust toolchain via `rustup`, not the distro's `cargo`/`rust`/`selinux-policy-devel` RPM packages — on an actual Fedora build host (or Koji/mock) with those installed, the same spec should build without that flag. Also not yet done, and explicitly out of this spec's scope until it exists: `cargo vendor`-based offline building for real network-isolated Koji/mock builds (tracked under §3.10).

### X-Forwarded-For trust + shared-hosting PHP HTTP-remote mode (user request, mid-chapter)

Not a numbered §3.x sub-chapter — a direct user request to make the write key ("API key") actually usable from real shared hosting, where `ext-ffi` and `proc_open` are both commonly unavailable. Added: `FOSSH_TRUST_FORWARDED_FOR` (opt-in, off by default — `fossh-cgi/src/forwarded.rs`, 5 tests, ADR-0025) so a trusted relay's forwarded IP can be honored without any deployment silently trusting a spoofable header by default; a third transport in `bindings/php/src/Client.php` (HTTP-remote, bearer-token auth over plain HTTPS via `curl` or PHP's stream wrapper, whichever is available, ~2s timeout, never throws); `docs/INTEGRATION-php.md` covering API-key creation, the shared-hosting HTTP mode, why `FOSSH_TRUST_FORWARDED_FOR` matters for correct per-visitor counts in that mode specifically, a WordPress snippet, and a short note that running alongside Google Analytics/GTM needs no special handling (no cookies, no client-side script, nothing to conflict with) — also reflected in `RULES.md` §5. Verified: full Rust suite (250 tests, root workspace) + `fossh-ffi`'s separate workspace (32 tests) all pass, clippy/fmt clean. The PHP client itself could not be run against a real PHP interpreter (none installed in this environment, same limitation as the rest of M6) — reviewed by hand instead; see the file's own comments for the specific `curl`/stream-context/JSON-shape reasoning.
