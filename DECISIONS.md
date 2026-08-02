# DECISIONS.md — Architecture Decision Record

One entry per non-obvious choice. Newest at the bottom. Format: decision, alternatives rejected, reason.

---

## ADR-0001 — Edition 2024 over 2021

**Decision:** All crates use `edition = "2024"`.
**Alternatives rejected:** Edition 2021 (more widely pinned in older tutorials/CI images).
**Reason:** New project, no legacy constraint. 2024 has been stable well over a year on the toolchain used to build this (rustc 1.97.1); no reason to start on an older edition.

---

## ADR-0002 — `fossh-ffi` is a separate Cargo workspace, not a member of the root workspace

**Decision:** `crates/fossh-ffi` has its own `[workspace]` root (its own `Cargo.lock`) and is excluded from the top-level workspace `members`. It depends on `fossh-core`, `fossh-store`, `fossh-ingest` via relative path dependencies.

**Alternatives rejected:**
1. Single workspace, set `panic = "abort"` workspace-wide (breaks `catch_unwind` in the FFI boundary — S2 and §11 both require panics to be caught at the FFI boundary via `catch_unwind`, which only works under `panic = "unwind"`).
2. Single workspace, `panic = "unwind"` workspace-wide (loses the smaller/faster binaries `panic = "abort"` gives `fossh-cgi`/`fossh-fcgi`/`fossh-cli`, which never need to catch a panic — S2 has them exit non-zero instead).
3. Per-package profile override for `panic` (not supported by Cargo — `panic`, `lto`, and `rpath` are workspace-graph-wide settings and cannot be overridden per package, because every crate linked together must agree on panic strategy).

**Reason:** Cargo cannot mix panic strategies within one build graph. Splitting `fossh-ffi` into its own workspace is the standard way around this when a cdylib needs `unwind` alongside sibling binaries that want `abort`. Cost: a second `Cargo.lock` to keep in sync by hand when shared dependency versions bump; acceptable given how rarely those versions will move.

---

## ADR-0003 — Hand-rolled CLI argument parsing instead of `clap`

**Decision:** `fossh-cli` parses `argv` by hand.
**Alternatives rejected:** `clap` (derive or builder API).
**Reason:** §5's dependency allowlist is exhaustive and does not include an arg-parsing crate; S11 caps the project at ≤15 direct / ≤60 total dependencies for the default feature set. `clap` alone plus its transitive tree (`clap_builder`, `anstream`, `anstyle`, `anstyle-parse`, `anstyle-query`, `colorchoice`, `strsim`, `terminal_size`, `is_terminal_polyfill`, `utf8parse`...) would consume a large fraction of that budget for a CLI with a small, stable set of subcommands. The project's whole ethos (§18, "restraint") favors hand-rolling a ~small, boring parser over pulling in a general-purpose one. Cost: less polished `--help`/error output, no shell-completion generation. Revisit if the CLI surface grows well past what's specified in §9.

---

## ADR-0004 — Config struct + file-search/parse lives in `fossh-core`, not a new crate

**Decision:** The `fossh.toml` search path (`$FOSSH_CONFIG`, `./fossh.toml`, `/etc/fossh/fossh.toml`), env var override (`FOSSH_*`), and parsing live in `fossh-core::config`, even though that module performs filesystem I/O (reading the config file) and `fossh-core` is otherwise "pure logic, no I/O" per §5.

**Alternatives rejected:**
1. A new `fossh-config` crate (not in §5's layout; a new crate needs its own justification per §0, and config loading is small enough that a dedicated crate is overhead, not architecture).
2. Duplicating config search/parse/merge logic separately inside `fossh-cgi`, `fossh-fcgi`, and `fossh-cli` (three copies of the same logic to keep in sync — worse than bending the "no I/O" description for one module).

**Reason:** §5 describes `fossh-core` as "pure logic ... no I/O, no unsafe, 100% unit-testable" in the context of validation/sanitize/hash/k-anon — the invariant that actually matters (P1–P10, S1–S12) is about the *event data path*, not process bootstrap. Config loading happens once at startup, outside the hot path, and is straightforward to unit-test by injecting a path. Treated as a pragmatic exception, not a precedent for adding more I/O to the crate.

---

## ADR-0005 — Git identity for this repository

**Decision:** This repo's local `git config user.name` / `user.email` are set to `$0aptile` / `s0aptile@users.noreply.github.com` (repo-local config only — never `--global`), per §19.2/§19.4.11.

**Note:** `s0aptile@users.noreply.github.com` is a placeholder in the standard GitHub-noreply shape. The real GitHub-issued noreply address (the `ID+username@users.noreply.github.com` form, if "keep my email private" is enabled) is only visible from inside the actual `s0aptile` GitHub account's own Settings → Emails page — nothing in this environment can look that up, and doing so would mean linking this session to that account, which runs against the anonymity goal of §19.2. Swap this address before the first real push if GitHub's enforced-privacy form is required for that account.

---

## ADR-0007 — `props: Vec<(Key, Val)>` instead of the `SmallVec` shown in §6

**Decision:** `Event::props` is `Vec<(Key, Val)>`, with the S4 16-item cap enforced at construction/validation time, not in the type.
**Alternatives rejected:** `SmallVec<[(Key, Val); 16]>` as literally sketched in §6's illustrative struct.
**Reason:** §6's struct is explicitly "wire + internal" illustrative shape, not a literal type mandate — and `smallvec` is not in §5's dependency allowlist. Adding it would need its own ADR justification for a pure inline-storage micro-optimization on an already-bounded (≤16 elements, ≤256 B each) collection. Not worth the dependency.

---

## ADR-0008 — Property *values* use the P8 grammar with the S4 length cap, not the literal `{1,64}` from P8's prose

**Decision:** `Name`, `Key`, and `Val` all share the charset `[a-z0-9_.:-]`; `Name`/`Key` cap at 64 bytes, `Val` caps at 256 bytes.
**Alternatives rejected:** Applying `[a-z0-9_.:-]{1,64}` literally to property values too, as P8's sentence reads if taken word-for-word.
**Reason:** P8 and S4 disagree on the face of it — P8 says names, keys, *and values* match `{1,64}`; S4 separately caps "property value: 256 B". Since a value can't simultaneously be capped at 64 and 256, one of the two has to give, and S4's per-field byte budget is the more specific, more clearly load-bearing number (it's the one referenced by the request-size math elsewhere in §4). Treated the charset as the shared, portable part of P8's intent and the length as S4's job per field.

---

## ADR-0009 — Registrable-domain extraction is a curated-suffix heuristic, not a full Public Suffix List

**Decision:** `Host::from_referrer_url` reduces a referrer URL's host to "last two labels", except for a hand-maintained list of ~47 common multi-part suffixes (`co.uk`, `com.tr`, `co.jp`, ...) where it keeps three.
**Alternatives rejected:** Vendoring the real Public Suffix List (~250 KB, thousands of entries, needs periodic refresh from an external source) for byte-perfect eTLD+1 extraction.
**Reason:** Getting this wrong misattributes a referring site's coarse identity (`example.co.uk` rows landing under a `co.uk` bucket for suffixes not in the curated list) — an analytics *accuracy* cost, not a privacy one; `Host` never contains anything that identifies a visitor either way. Full PSL support is a plausible future addition if referrer accuracy turns out to matter enough to justify the size and maintenance cost; not justified for the alpha. Documented as a known gap, not a silent limitation.

---

## ADR-0010 — Credential handling for local privileged commands

**Decision:** No password is ever placed in a shell command, file, or log from this session. Where a build step genuinely needs `sudo` (installing a missing system package), the exact command is surfaced for the user to run themselves via their own shell, rather than piping a credential through a tool call.
**Reason:** A plaintext password embedded in a command is retained wherever that command is recorded. Standard toolchain setup (rustup, cargo, musl target) needed no elevated privileges at all; `cc`/`gcc` were already present on this machine, so this has not come up in practice for M1.

---
