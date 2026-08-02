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

## ADR-0006 — `props: Vec<(Key, Val)>` instead of the `SmallVec` shown in §6

**Decision:** `Event::props` is `Vec<(Key, Val)>`, with the S4 16-item cap enforced at construction/validation time, not in the type.
**Alternatives rejected:** `SmallVec<[(Key, Val); 16]>` as literally sketched in §6's illustrative struct.
**Reason:** §6's struct is explicitly "wire + internal" illustrative shape, not a literal type mandate — and `smallvec` is not in §5's dependency allowlist. Adding it would need its own ADR justification for a pure inline-storage micro-optimization on an already-bounded (≤16 elements, ≤256 B each) collection. Not worth the dependency.

---

## ADR-0007 — Property *values* use the P8 grammar with the S4 length cap, not the literal `{1,64}` from P8's prose

**Decision:** `Name`, `Key`, and `Val` all share the charset `[a-z0-9_.:-]`; `Name`/`Key` cap at 64 bytes, `Val` caps at 256 bytes.
**Alternatives rejected:** Applying `[a-z0-9_.:-]{1,64}` literally to property values too, as P8's sentence reads if taken word-for-word.
**Reason:** P8 and S4 disagree on the face of it — P8 says names, keys, *and values* match `{1,64}`; S4 separately caps "property value: 256 B". Since a value can't simultaneously be capped at 64 and 256, one of the two has to give, and S4's per-field byte budget is the more specific, more clearly load-bearing number (it's the one referenced by the request-size math elsewhere in §4). Treated the charset as the shared, portable part of P8's intent and the length as S4's job per field.

---

## ADR-0008 — Registrable-domain extraction is a curated-suffix heuristic, not a full Public Suffix List

**Decision:** `Host::from_referrer_url` reduces a referrer URL's host to "last two labels", except for a hand-maintained list of ~47 common multi-part suffixes (`co.uk`, `com.tr`, `co.jp`, ...) where it keeps three.
**Alternatives rejected:** Vendoring the real Public Suffix List (~250 KB, thousands of entries, needs periodic refresh from an external source) for byte-perfect eTLD+1 extraction.
**Reason:** Getting this wrong misattributes a referring site's coarse identity (`example.co.uk` rows landing under a `co.uk` bucket for suffixes not in the curated list) — an analytics *accuracy* cost, not a privacy one; `Host` never contains anything that identifies a visitor either way. Full PSL support is a plausible future addition if referrer accuracy turns out to matter enough to justify the size and maintenance cost; not justified for the alpha. Documented as a known gap, not a silent limitation.

---

## ADR-0009 — `rollup_hourly.uniques` is `BLOB`, plus an added `value_hist BLOB` column, beyond §6's literal `CREATE TABLE`

**Decision:** `uniques` stores a serialized HyperLogLog sketch (`BLOB NOT NULL`), not an `INTEGER` count. A `value_hist BLOB` column (a mergeable log2-bucket histogram, `fossh_core::hist::Histogram`) is added; `p50`/`p95` stay `INTEGER` as shown, but are point estimates recomputed from `value_hist` on every upsert rather than the source of truth.
**Alternatives rejected:** Following §6's `CREATE TABLE` literally (`uniques INTEGER`, no `value_hist`).
**Reason:** §6's own prose ("stored as a BLOB, so raw visitor values can be deleted at day boundary while cardinality survives") contradicts the `INTEGER` in the SQL snippet three lines below it — they can't both be right. A rollup bucket gets updated incrementally across many compactor passes within its hour; correctly folding one more event into an existing bucket's uniques/percentiles requires a mergeable sketch, not a number you can no longer un-average. Full reasoning and the exact schema are in `schema.rs`'s module doc comment. Neither addition reopens P1 — both are aggregate/sketch data with no visitor-level content, and the column-set invariant test still pins an exact list.

---

## ADR-0010 — Property keys intern into the same `names` table as event names

**Decision:** `props.k REFERENCES names(id)` — no separate keys table.
**Reason:** §6 has no dedicated interning table for property keys, only `names`/`paths`/`refs`; keys and event names are both short allowlisted identifiers under the identical grammar (P8), so sharing one string-interning table is the natural reading rather than inventing a fourth table §6 never mentions.

---

## ADR-0011 — k-anonymity (P6) folds on estimated *uniques*, not *hits*

**Decision:** `Store::query_rollup`'s k-anonymity fold compares a group's estimated distinct-visitor count (`Hll::estimate()`) against `k`, not its event/hit count.
**Alternatives rejected:** Folding on `hits` (raw event volume) instead.
**Reason:** P6 says "grouped query result whose *bucket count* is below k" — ambiguous between the two metrics. The privacy property k-anonymity is actually protecting is "this row doesn't correspond to a handful of identifiable people," which is a statement about distinct visitors, not event volume — a page with 500 hits from 2 people is exactly the small-group case k-anonymity exists to hide, and folding only on hits would let it through.

---

## ADR-0012 — `path_id = 0` sentinel for "no path" in `rollup_hourly`

**Decision:** Events with no `path` (e.g. some `Action`/`Timing` events) roll up with `path_id = 0`, a value never assigned to a real interned path, rather than `NULL`.
**Reason:** `rollup_hourly` is `WITHOUT ROWID` with `path_id` as part of the composite `PRIMARY KEY`; SQLite implicitly forbids `NULL` in any column of a `WITHOUT ROWID` table's primary key (unlike an ordinary rowid table, where `events.path_id` — a plain nullable column, not part of a `WITHOUT ROWID` key — is `NULL` for the same case). `paths.id` is an `INTEGER PRIMARY KEY` (rowid alias), which SQLite starts allocating from `1`, so `0` is safe to reserve.

---

## ADR-0013 — Rate limiting and CORS use plain positioned file I/O, not `mmap`

**Decision:** `auth::NonceCache` (§8's nonce replay cache) and `ratelimit::TokenBucket` (S10) are backed by ordinary `std::fs::File` reads/writes at fixed offsets, not `memmap2`.
**Alternatives rejected:** Following S8/S10's literal "mmap'd" wording.
**Reason:** Every `memmap2` mapping call is `unsafe fn` — the kernel can change mapped bytes out from under Rust's aliasing model at any time, which is exactly what an `unsafe` boundary exists to flag. S1 forbids `unsafe` in every crate except `fossh-ffi`, and is explicitly one of the *hard*, non-negotiable invariants (§3/§4), ranked above "matches the spec's suggested implementation" in §19.1's own tie-break order (security invariant, priority 2, beats operator/developer ergonomics, priorities 4–5). A plain read-modify-write under concurrent CGI processes still gives the "no lock, tolerate ±1 slop" behavior S10 explicitly asks for — the *behavior* is preserved even though the *mechanism* changed. Same reasoning applies to §7.1's spool writer, which uses a single `std::fs::File::write` call instead of a raw `libc::write` (every `libc` FFI call is also `unsafe fn`) — see `spool.rs`'s module doc comment for why a single `write()` call is still exactly one `write(2)` syscall without needing that call.

---

## ADR-0014 — `sites.public` column, added beyond §6's literal `CREATE TABLE`

**Decision:** `sites` gains `public INTEGER NOT NULL DEFAULT 0`. Public (bearer-mode) sites get half the configured `rate_limit` (`per_sec`/`burst`, minimum 1 each) and are the only sites whose `Origin` header is ever echoed into `Access-Control-Allow-Origin`.
**Alternatives rejected:** Leaving `public` out (§6's schema doesn't have it) and finding some other way to satisfy §8's "such keys are flagged `public=1` at creation, are rate-limited harder, and can only emit event names on the site's allowlist."
**Reason:** §8 refers to a `public` flag that §6's own `CREATE TABLE sites` never defines — the same kind of gap as ADR-0009's `uniques`/`value_hist`. There's no other natural home for it, and it directly answers two things the spec otherwise leaves open: how much harder public keys are rate-limited (half the configured bucket, a simple, explicit default), and — completely unspecified anywhere — what governs the CORS echo in §7.1's response table ("`Access-Control-Allow-Origin: <echoed only if origin ∈ site allowlist>`"). Reusing `sites.allowlist` for that would be wrong: §6 explicitly scopes that field to "permitted event names / prop keys," not origins, and inventing a *second*, undocumented allowlist for origins is worse than tying CORS echo to the one boolean the spec already gestures at (public/browser-facing vs. signed/server-to-server, where CORS doesn't apply at all).

---

## ADR-0015 — Signed-mode HMAC verification uses `key_hash` as the live signing key

**Decision:** `sig = BLAKE3-keyed(key_material, canonical)` where `key_material` is `site.key_hash` (`BLAKE3(write_key)`, stored server-side) on both ends — the client computes it once from the write key it was issued and signs with it; the server never needs, transmits, or stores the original write key at all.
**Alternatives rejected:**
1. Reading §8 fully literally (`sig = BLAKE3-keyed(write_key, canonical)` using the raw key) — impossible to verify server-side given "only `BLAKE3(key)` is stored" in the very same section; a keyed hash can't be checked against a one-way hash of its key.
2. Storing the raw `write_key` server-side after all, to make literal HMAC-with-the-raw-key verification possible — directly contradicts §8's explicit "the key itself is never stored," which is unambiguous and not in tension with anything else.

**Reason:** §8 contains two claims that can't both be true as written; something has to give, and undoing "the key itself is never stored" is a much bigger invariant to break than reinterpreting which 32 bytes "the signing key" refers to. Treating the *hash* as the actual keyed-hash key is standard practice for systems that store `hash(secret)` and use the hash as the live verifier (its secrecy is equivalent to the original secret's — both require having seen the credential once, and `BLAKE3` isn't invertible) — it just isn't the literal string an operator pastes into a client's config file. `auth.rs` documents this in detail and names the parameter `signing_key`, not `write_key`, everywhere it appears, specifically so a future reader doesn't wire in the raw key by mistake.

---

## ADR-0016 — Compiled binary names match crate directory names (`fossh-cgi`, `fossh-cli` → `fossh`, `fossh-fcgi`), not all literally `fossh`

**Decision:** The CLI's compiled binary is `fossh` (matching §9's explicit `fossh init` / `fossh site create` / ... invocations verbatim). The CGI and FastCGI binaries are `fossh-cgi` and `fossh-fcgi` — their own crate names — not `fossh`.
**Alternatives rejected:** Naming all three binaries `fossh`, as §1's prose ("fossh CGI binary") and §13's size-gate wording ("Stripped musl CGI binary") suggest in isolation.
**Reason:** Cargo builds every crate in a workspace into one shared `target/` directory; two packages defining a binary with the identical name is a build-time conflict, not just a deployment nuisance — `cargo build --workspace` cannot produce two different files both named `target/release/fossh`. Practically, a CGI binary is always wired into a webserver via an explicit, operator-chosen path in that webserver's own config (`ScriptAlias`, `fastcgi_pass`, etc.) — never resolved through `$PATH` the way a CLI command is — so its on-disk filename is far less load-bearing than the CLI's, which people actually type. `DEPLOY-{apache,nginx,caddy}.md` reference `fossh-cgi` by that name in their example config blocks.

---

## ADR-0017 — `fossh-cgi` reads `FOSSH_*` env vars directly; it never calls `Config::load()`

**Decision:** The CGI binary reads `FOSSH_DATA_DIR`, `FOSSH_SALT_DIR`, `FOSSH_RATE_LIMIT_PER_SEC`, `FOSSH_RATE_LIMIT_BURST`, `FOSSH_RESPECT_OPTOUT_SIGNALS` straight from the process environment — same names and defaults as `Config`'s own env-override pass — instead of parsing `fossh.toml`. `fossh-cli`'s long-running commands (`maintain`, `query`, ...) use `Config::load()` as normal.
**Alternatives rejected:** Having `fossh-cgi` call `Config::load()` too, for consistency with `fossh-cli`.
**Reason:** §7.1 sets a < 5 ms p99 budget for the CGI hot path and says outright "startup cost matters." `Config::load()` searches up to three candidate paths and parses TOML on every single invocation — a real, if small, cost that buys nothing a webserver's own `SetEnv`/`fastcgi_param` directives don't already solve, which is the standard way CGI processes receive configuration in the first place. Operators who want one source of truth can have their webserver config reference the same values `fossh.toml` holds; `fossh-cgi` doesn't need to be the one parsing it.

**Follow-on catch, while integration-testing this end to end:** `fossh-cgi`'s salt-directory resolution had drifted from `Config.salt_dir` — `handler.rs` was computing a *per-site* salt path (`data_dir/sites/<id>/salt`) instead of using one shared directory, unlike spool/ratelimit/nonces, which genuinely are per-site. Fixed to share one salt directory across all sites, which is sound because P2's hash formula already mixes `site_id` into `visitor_id` (`BLAKE3(daily_salt ‖ client_ip ‖ ua_string ‖ site_id)`) — site separation comes from that, not from an unshared salt. A per-site salt would've been a pointless duplication that left `Config.salt_dir` dead code. Caught by actually running `init` → `site create` → a live CGI request end to end, not by any unit test — none of them exercised both halves (M1's `Config` and M3's `handler.rs`) against each other.

---

## ADR-0018 — S8 file-permission enforcement: refuse for the database, tighten for the spool

**Decision:** `fossh_store::Store::open` actively enforces `0600` on the database file: a brand-new file is created with `0600` before SQLite ever opens it (closing the umask-default-permissions race window), and an *existing* file found with wider permissions makes `open` return `Err(StoreError::PermissionsTooOpen)` with the exact `chmod` command in the message — it does not silently rewrite the file's permissions. `fossh_ingest::spool::append_frame` also enforces `0600`, but tightens a wider-permission file in place rather than refusing.
**Reason:** S8 says plainly: "DB and spool files `0600`... Refuse to start if permissions are wider; print the exact `chmod` to run" — an invariant that was simply unimplemented until `fossh doctor` (M4) was run against a real installation and reported the database file at `644`. Caught by actually running `init` → `site create` → a live CGI request → `maintain` → `query` → `doctor` end to end, the same way the `key_hash` bearer-auth bug (ADR-0015's implementation) and the salt-directory drift (ADR-0017) were — none of the three showed up in unit tests, because each one only breaks when two components that were tested in isolation are wired together for real.

The database and the spool get different treatment on purpose: `Store::open` is called by `fossh-cli`'s long-running, operator-invoked commands, where refusing to start and asking a human to run one `chmod` command is the right level of friction for a file meant to persist and hold everything the retention window covers. `append_frame` runs on the `fossh-cgi` hot path, where §7.1's "never block the request" outweighs strict refusal — a spool file is transient (drained and deleted by the next `maintain`/compactor pass within, at most, a rotation cycle), so silently tightening its permissions and moving on is the safer choice for availability without meaningfully weakening S8's intent.

---

## ADR-0019 — `fossh-ffi` authenticates once at `fossh_set_key`, not per call

**Decision:** `fossh_set_key` looks the presented key up against the database directly (parse the `fossh_<slug>_<base32>` token, hash the decoded key, compare to `sites.key_hash`) and caches the resolved site (id + allowlist) in the context. `fossh_pageview`/`fossh_event`/`fossh_timing`/`fossh_record_env` all trust that cached identity — none of them re-derive an HMAC signature the way `fossh-cgi` does per request (§8).
**Alternatives rejected:** Requiring every recording call to carry (or the context to re-verify) a signature, mirroring the network-facing CGI auth flow.
**Reason:** §8's signed-request flow exists to prove, over a network, that whoever is calling `/e` actually possesses a site's write key — a real adversary model for a CGI endpoint anything on the internet can reach. An FFI call has no network hop: the host process *is* the caller, in the same address space, and if it's malicious or compromised, the extra HMAC math wouldn't have stopped it — it can already call `fossh_set_key` with any key it wants, same as it can call any other function in the process linking against it. Re-verifying a signature on every call would add cost and complexity against a threat this deployment shape doesn't have.

---

## ADR-0020 — `fossh_record_env` picks JSON-body vs. query-string by presence of a body, not a route

**Decision:** `fossh_record_env` parses the body as a JSON event/batch (`pipeline::from_json_body`) whenever `body_len > 0`, and falls back to `QUERY_STRING` (`pipeline::from_query_string`) otherwise — mirroring `POST /e` vs. `GET /e.gif`, but selected by data present rather than by matching `PATH_INFO` against `/e`/`/e.gif` the way `fossh-cgi` does.
**Reason:** §11 gives this one function to cover what `fossh-cgi` splits across two routes; there's no second entry point to distinguish by name. Presence-of-body is the natural signal the two existing paths already imply (a beacon-style `GET` has no body by construction; a JSON POST does), and it means a host application handing foSSH a raw CGI-shaped environment doesn't also have to get `PATH_INFO` conventions exactly right for this to work.

---

## ADR-0021 — Miri coverage is scoped to `opt_str`/`write_c_string_truncated`, not the full `fossh-ffi` test suite

**Decision:** `cargo +nightly miri test` only targets the `miri_safe` module (`opt_str`, `write_c_string_truncated` — pulled out as standalone functions specifically so they don't need a live `fossh_ctx`). The other 23 tests, which exercise the full `fossh_init`/`fossh_set_key`/recording flow, are not run under Miri.
**Reason:** Every one of those 23 tests goes through `Store::open`, which calls into `rusqlite`'s `bundled` feature — real, compiled SQLite C source, linked in and called via FFI. Miri interprets Rust MIR; it has no way to execute arbitrary compiled C, and fails immediately on the first SQLite call (`can't call foreign function 'sqlite3_threadsafe'`), even with `MIRIFLAGS=-Zmiri-disable-isolation` set. This is a documented, fundamental Miri limitation, not a gap in this project's code. It also isn't a meaningful gap in *coverage* of what S1 actually asks Miri to check: `opt_str` and `write_c_string_truncated` are the only two functions in the entire codebase — across every crate, since `fossh-ffi` is the only one `unsafe` is permitted in at all — that dereference a raw pointer without first going through `fossh_ctx`/`Store`. Every other `unsafe` block in `lib.rs` is a thin `CStr::from_ptr`/`&*ctx`/slice-from-raw-parts conversion at a function boundary, immediately handed off to ordinary safe Rust; there is no unsafe logic anywhere in the project that Miri could exercise by going deeper into the `Store`-backed tests than it already does before hitting the SQLite wall.

---

## ADR-0022 — `FosshError` is `pub` and exported as `fossh_err_t`

**Decision:** The error-code enum (previously private, returned to C only as bare `int32_t`) is now `pub`, individually documented per variant, and explicitly included in `cbindgen.toml` so the generated header gets a real `fossh_err_t` C11 enum (`FOSSH_ERR_T_REJECTED`, etc.) instead of C callers writing magic numbers like `-5`.
**Reason:** Exposing the enum *definition* — fixed variant names known at compile time — is not the "never leak a dynamic message" constraint S2/§11 actually care about (that's about runtime strings built from caller-controlled input, e.g. echoing back a rejected event name). Named constants are free ergonomics for every binding built on top of this header; verified end to end with a real, independently-compiled C program linking `libfossh.so` (`gcc -Wall -Wextra`, zero warnings) that checks `FOSSH_ERR_T_REJECTED` by name — see the M6 commit.

---

## ADR-0023 — Credential handling for local privileged commands

**Decision:** No password is ever placed in a shell command, file, or log from this session. Where a build step genuinely needs `sudo` (installing a missing system package), the exact command is surfaced for the user to run themselves via their own shell, rather than piping a credential through a tool call.
**Reason:** A plaintext password embedded in a command is retained wherever that command is recorded. Standard toolchain setup (rustup, cargo, musl target) needed no elevated privileges at all; `cc`/`gcc` were already present on this machine.

**Open item, M3:** the `x86_64-unknown-linux-musl` release build (needed to actually check §17's "stripped musl CGI binary < 3 MB" gate) fails at the `libsqlite3-sys` build-script step — it needs `x86_64-linux-musl-gcc`, which isn't installed, and installing it needs `sudo dnf install musl-gcc`. Asked the user; decided to defer rather than handle the password. The native (glibc) `--release` build works today and is a reasonable stand-in for now: `fossh-cgi` strips to 482 KB, comfortably under the 3 MB budget even before musl's typically-larger static-link footprint. Actually verifying the real musl artifact is carried forward as an M8 checklist item.

---

## ADR-0024 — glibc-floor check lives in `doctor`/`glibc-check`, not `fossh-cgi`'s per-request path; both share one `ldd`-invoking helper

**Decision:** The Fedora-native chapter's §2.5/§3.1 glibc-floor check ("ship a startup check that detects the host's glibc version and refuses to run... rather than failing with an opaque dynamic-linker error") is implemented as: a pure parser/comparator in `fossh_core::glibc_gate` (no I/O), plus exactly one I/O-performing caller — `fossh_cli::common::detect_glibc_version()` — shared by both `fossh doctor` (folded into its existing pass/fail table) and the new standalone `fossh glibc-check` (meant for a systemd unit's `ExecStartPre=`, §3.2/§3.11, once per service (re)start). It is deliberately **not** called from `fossh-cgi`'s `main()`, which is re-exec'd by the webserver on every single HTTP request under the CGI model — the host's glibc version cannot change between one request and the next, so spawning `ldd` per request would tax §7.1's documented sub-5ms p99 budget for zero benefit. The only alternative that avoids a subprocess entirely (`libc::gnu_get_libc_version()`, an in-process call) needs `unsafe extern "C"` FFI, which S1 confines to `fossh-ffi` alone — not worth reopening for this one check.
**Alternatives rejected:** (a) checking inside `fossh-cgi` per request — rejected on the performance grounds above; (b) using `libc`'s `gnu_get_libc_version` directly from `fossh-cgi` — rejected, would require relaxing S1's `#![forbid(unsafe_code)]` in a crate that currently has zero `unsafe` of its own; (c) each caller (`doctor`, `glibc-check`) independently spawning and parsing `ldd` — this is what shipped first, and turned out to be the actual bug: both independently called `Command::output()` and inspected `stdout` **without checking `output.status`**, so an `ldd` that itself failed (non-zero exit — precisely the kind of half-broken glibc install this check exists to catch) but still printed something shaped like `MAJOR.MINOR` on stdout parsed as a clean pass. Caught by an adversarial-review subagent pass (see DURUM.md's §3.1 retrospective) before this was considered done, empirically confirmed against the real compiled binary with a shadowed fake `ldd` on `$PATH`, fixed by collapsing both call sites onto the one `detect_glibc_version()` helper in `common.rs`, which checks `status.success()` before ever trusting `stdout`.
**Reason:** one I/O helper means a future fix (this one, or the next one) only has one call site to fix, not two that can silently drift back apart — which is exactly how the exit-status bug happened the first time.
**Known gap, acknowledged rather than silently left implicit:** as of this ADR, nothing *automatically* invokes either check yet — `doctor` is operator-run by hand, and `glibc-check`'s systemd `ExecStartPre=` wiring doesn't exist until §3.2's unit file is written. A below-floor host can stand up `fossh-cgi` today through the pre-existing (pre-chapter) Apache/nginx CGI deployment shape with nothing stopping it. The floor check is implemented; it is not yet load-bearing anywhere. DURUM.md tracks this distinction explicitly so it isn't mistaken for enforcement that doesn't exist yet.

---

## ADR-0025 — Opt-in `X-Forwarded-For` trust (`FOSSH_TRUST_FORWARDED_FOR`), for reverse-proxy and shared-hosting-relay deployments

**Decision:** `fossh-cgi` reads `REMOTE_ADDR` as-is unless the operator explicitly sets `FOSSH_TRUST_FORWARDED_FOR=1`, in which case it takes the leftmost entry of `X-Forwarded-For` (if present) instead. Implemented as a pure function (`fossh-cgi/src/forwarded.rs::resolve_client_ip`, 5 tests) called once in `main.rs`'s `read_cgi_env`, before `handler::authenticate` ever runs.
**Context:** two real deployment shapes need this to produce correct per-visitor stats (P2's `BLAKE3(daily_salt ‖ client_ip ‖ ua_string ‖ site_id)` hashing) rather than silently collapsing every visitor into one: (a) nginx terminating the real client connection and proxying to `fcgiwrap`/`fossh-cgi` over a Unix socket — nginx already sets `REMOTE_ADDR` correctly for its own CGI dispatch in the common case, but an operator running nginx behind another edge (Cloudflare) that doesn't fix up `real_ip` first would otherwise see every visitor collapse to the edge's IP; (b) a shared-hosting PHP script (`bindings/php/src/Client.php`'s HTTP-remote mode, `docs/INTEGRATION-php.md`) making a server-side relay call to a foSSH instance running elsewhere — the TCP peer address on that call is *always* the shared host's own egress IP, never the original visitor's, with no way around that at the connection layer at all; only the relaying script itself knows the real visitor IP (from its own `$_SERVER['REMOTE_ADDR']`), and can only communicate it via a header/field the receiving end chooses to trust.
**Alternatives rejected:** (a) always trusting `X-Forwarded-For` unconditionally — rejected, since any caller could then forge a client identity for hashing/rate-limiting purposes on a deployment that *isn't* actually behind a relay; (b) a bespoke JSON body field (`"client_ip": "..."`) instead of the standard header — rejected as extra surface on the already-tested ingest JSON schema (`fossh-ingest::pipeline`) for no benefit over reusing the header every HTTP client/library already knows how to set; (c) trusting it unconditionally once a request is already authenticated (bearer/signed) — rejected even though the trust boundary is arguably no weaker (a valid write-key holder can already submit somewhat-fabricated telemetry; that's inherent to server-side/beacon-based analytics, not something this changes) because *silent*, non-opt-in trust of a spoofable header is a worse default to ship than an explicit flag, independent of how bad the actual exposure is.
**Reason:** matches the standard, well-understood pattern other web frameworks use for the identical problem (Rails' `config.action_dispatch.trusted_proxies`, Express's `trust proxy`) — off by default, on only because an operator who understands their own deployment topology said so.

---

## ADR-0026 — New crate `fossh-admin`; `SHA256` (not `BLAKE3`) for the setup token specifically

**Decision:** A new crate, `fossh-admin`, holds watchdog-adjacent security primitives that both `fossh-tui` (direct Rust dependency) and — once §3.3/§3.4 exist — the OCaml watchdog's FFI surface need: starting with the §2.6 first-run setup-token model (`generate`/`verify`/`write_token_file`/`burn`, 8 tests), and later the §3.6 tamper-detection manifest and §2.1 challenge-response keypair/session logic as those sub-chapters land. This keeps the future watchdog's own dependency tree minimal (§3.3's explicit rationale) by pushing crypto into an already-audited Rust crate it calls over FFI, the same shape `fossh-ffi` already established for the telemetry ingest path — not a new pattern, an extension of one already in use.
Setup-token hashing uses `SHA256` (the `sha2` crate — RustCrypto, not hand-rolled), specifically because §2.6 names that primitive by name, twice, not because it needed picking. Everywhere else in this project uses `BLAKE3`; this is the one deliberate exception, and `TokenHash` is a newtype specifically so a `BLAKE3` digest from elsewhere in the codebase can never be passed where a token hash is expected, or vice versa, and compile anyway.
**Alternatives rejected:** (a) using `BLAKE3` here too, for project-wide consistency — rejected; §2.6 is explicit and there's no reason to relitigate a locked decision purely for uniformity; (b) hand-rolling `SHA256` (matching this project's general preference for hand-rolled implementations over a broad dependency allowlist, e.g. `base32`, `hll`, CRC-32) — rejected specifically for a cryptographic hash: that general preference applies to logic simple enough to write and verify against known test vectors with confidence (checksums, encodings, cardinality sketches), not to primitives where a subtle bug is far more likely and far more costly; `sha2` is small, single-purpose, and about as widely audited as a Rust crate gets.
**`burn`'s ordering** (invalidate the stored hash, *then* delete the plaintext file — not the reverse) is deliberate, not incidental: true atomicity across two separate on-disk artifacts isn't available in plain POSIX without a shared transaction log. Invalidating first means a crash between the two steps leaves, at worst, an inert leftover plaintext file with no hash left to verify against; deleting first would leave the strictly worse window of a live, replayable hash with the "already used" plaintext still gone. Tested directly (`burn_does_not_delete_the_file_if_hash_invalidation_fails` forces the first step to fail and asserts the plaintext file survives).

---
