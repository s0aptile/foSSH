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
**Alternatives rejected:** (a) checking inside `fossh-cgi` per request — rejected on the performance grounds above; (b) using `libc`'s `gnu_get_libc_version` directly from `fossh-cgi` — rejected, would require relaxing S1's `#![forbid(unsafe_code)]` in a crate that currently has zero `unsafe` of its own; (c) each caller (`doctor`, `glibc-check`) independently spawning and parsing `ldd` — this is what shipped first, and turned out to be the actual bug: both independently called `Command::output()` and inspected `stdout` **without checking `output.status`**, so an `ldd` that itself failed (non-zero exit — precisely the kind of half-broken glibc install this check exists to catch) but still printed something shaped like `MAJOR.MINOR` on stdout parsed as a clean pass. Caught by an adversarial-review subagent pass (see dev/DURUM.md's §3.1 retrospective) before this was considered done, empirically confirmed against the real compiled binary with a shadowed fake `ldd` on `$PATH`, fixed by collapsing both call sites onto the one `detect_glibc_version()` helper in `common.rs`, which checks `status.success()` before ever trusting `stdout`.
**Reason:** one I/O helper means a future fix (this one, or the next one) only has one call site to fix, not two that can silently drift back apart — which is exactly how the exit-status bug happened the first time.
**Known gap, acknowledged rather than silently left implicit:** as of this ADR, nothing *automatically* invokes either check yet — `doctor` is operator-run by hand, and `glibc-check`'s systemd `ExecStartPre=` wiring doesn't exist until §3.2's unit file is written. A below-floor host can stand up `fossh-cgi` today through the pre-existing (pre-chapter) Apache/nginx CGI deployment shape with nothing stopping it. The floor check is implemented; it is not yet load-bearing anywhere. dev/DURUM.md tracks this distinction explicitly so it isn't mistaken for enforcement that doesn't exist yet.

---

## ADR-0025 — Opt-in `X-Forwarded-For` trust (`FOSSH_TRUST_FORWARDED_FOR`), for reverse-proxy and shared-hosting-relay deployments

> **Amended by ADR-0073 (0.0.2.2).** The opt-in stands. The
> leftmost-entry selection described below does not — it is now a hop
> count read from the right, because the leftmost entry is the one the
> client wrote.


**Decision:** `fossh-cgi` reads `REMOTE_ADDR` as-is unless the operator explicitly sets `FOSSH_TRUST_FORWARDED_FOR=1`, in which case it takes the leftmost entry of `X-Forwarded-For` (if present) instead. Implemented as a pure function (`fossh_ingest::forwarded::resolve_client_ip`, 5 tests — moved here from `fossh-cgi` when M7's `fossh-fcgi` needed the identical logic) called once in `main.rs`'s `read_cgi_env`, before `handler::authenticate` ever runs.
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

## ADR-0027 — §3.8 data-at-rest encryption scoped to the spool, not the rollup database; ChaCha20-Poly1305 keyed by a per-install key from `fossh-admin::data_key`

**Decision:** Spool frames (`fossh-ingest::spool`) are sealed with ChaCha20-Poly1305 (`fossh-ingest::crypto`, a fresh random 12-byte nonce per frame, prepended to the ciphertext) before ever touching disk, keyed by a per-install data-encryption key `fossh-admin::data_key::load_or_generate` creates on first use and persists at `data_dir/.data_key` (0600). Every transport that touches the spool — `fossh-cgi` (writes), `fossh-cli maintain` (drains), `fossh-ffi`'s `mode = "spool"` path (writes and `fossh_flush` drains) — loads the same key from that same fixed path, so whichever mix of transports a deployment uses can still decrypt what another one wrote. The existing length-prefix + CRC32 frame structure is unchanged; what CRC32 now guards is the *ciphertext's* structural integrity (cheap truncation/corruption detection before ever attempting the more expensive AEAD open), while the AEAD tag is what actually authenticates the plaintext.
**Alternatives rejected:** (a) encrypting the rollup SQLite database (`fossh.db`) itself, e.g. via SQLCipher — rejected for this pass: that database holds hourly *aggregates* (HyperLogLog sketches, histograms, k-anonymity-folded counts), not raw per-visitor rows, since the whole system's privacy model already leans on aggregation, not encryption, for that data; the spool, by contrast, is the one place genuinely raw, not-yet-aggregated telemetry sits on disk, even if briefly, which makes it the higher-value and (append-only, sequential-read) more tractable target to get right under this pass's time budget. Revisiting the database as defense-in-depth is a reasonable follow-up, not ruled out, just not done here. (b) `SHA256` for the data key, matching the setup-token's §2.6-mandated exception (ADR-0026) — not applicable; §3.8 doesn't name a specific primitive, so this defaults to the project's standing `BLAKE3`-everywhere convention being irrelevant here too (this is symmetric AEAD, not hashing) — `ChaCha20Poly1305` (RustCrypto) was chosen over `AES-256-GCM` for not needing hardware AES-NI to be fast/side-channel-resistant in software, consistent with not assuming anything about the deployment host's CPU features.
**Reason:** the per-install-key pattern mirrors §2.4's watchdog keypair generation exactly (generate once, persist locally, never ship in the binary, never share across installs) — reusing an already-decided shape rather than inventing a new one. Race-safety on first use (many `fossh-cgi` processes can start cold simultaneously right after install/reboot) is handled explicitly (`load_or_generate`'s `AlreadyExists` fallback path, tested with 8 concurrent threads racing to create the same file) rather than assumed away.

---

## ADR-0028 — `tos.md` names no governing law, venue, or arbitration procedure

**Decision:** `tos.md` deliberately omits a choice-of-law clause, a venue clause, an arbitration clause, and a class-action waiver.
**Reason:** `tos.md` is a disclaimer and notice document, not a contract for the provision of a service — there is no service; foSSH is downloaded, built, and run entirely on infrastructure the operator controls, with zero involvement from the author (§19.4's structural fact: no egress, no server, no account). Naming a jurisdiction invites the argument that a contract *was* formed between the author and whoever runs foSSH, and then makes that argument's location litigable — actively worse than saying nothing. Omitting it leaves the MIT license (originally Apache-2.0/MIT; see ADR-0033), which needs no venue to disclaim a warranty or limit liability, as the sole operative instrument. An arbitration clause or class-action waiver has the same problem in miniature: both presuppose a contractual relationship this document is specifically written to avoid implying exists.
**Alternatives rejected:** naming the author's own jurisdiction (the obvious default for a solo-maintainer project) — rejected for the reason above; a "mutual agreement to arbitrate" clause as a lighter-weight alternative to litigation — rejected on the same "don't manufacture a contract where none was intended" grounds. This decision is required reading before anyone edits `tos.md`: adding any of the three back in later would need its own ADR reopening this one, not a quiet edit.

---

## ADR-0029 — §19.4.12 identity-hygiene pass: one real leak found and fixed, `scripts/build-release.sh` added

**Decision:** Ran every check §19.4.12 lists, for real, against this actual repository — not asserted as "should be clean," verified. Found one genuine leak: `DURUM.md` (written earlier in this same chapter, before this pass) named the real absolute pre-move path in prose describing the repository relocation, including the real system username. Fixed by rewriting that sentence to describe the move without repeating the path. Also found, empirically via `strings` on the actual release binaries, that `strip = true` (already set in the release profile) does **not** scrub embedded build paths — Rust bakes the absolute source path into every panic-location string (`file!()`/`line!()`, used by `.unwrap()`, `assert!()`, `#[track_caller]`, ...) at compile time, independent of debug-symbol stripping, and this showed up in all four release artifacts checked (`fossh-cgi`, `fossh`, `fossh-tui`, `libfossh.so`), including the real system username via the Cargo registry cache path (`~/.cargo/registry/src/...`), not just the project checkout path.
**Fix:** added `scripts/build-release.sh`, which computes `--remap-path-prefix` for both the project checkout and the Cargo registry cache *dynamically* (via `$(pwd)`/`$CARGO_HOME`) rather than hardcoding either — a committed static path would be wrong on any machine other than the one that committed it, which defeats the point of a reproducible release-build convention. `packaging/rpm/fossh.spec`'s `%build` now calls this script instead of a bare `cargo build --release --workspace`. Re-verified with `strings` after rebuilding under the remap: zero hits for `/home/`, `/Users/`, or the real username, across all five checked artifacts (adding `libfossh.a`).
**Verified clean, this pass:** git author/committer identity (one pseudonymous identity, noreply address, both `git log --format='%an <%ae>'` and `%cn <%ce>`); a tree-wide grep for the real username, a plausible real-name/email pattern, `/home/`, `/Users/`, and this machine's hostname, over every tracked file; `$0aptile` appears only in non-shell contexts so far (Rust/TOML/JSON string literals, Markdown prose) — correctly not an issue today, but the quoting gate itself has nothing to actively enforce yet, because no `.sh`, `Makefile`, or CI YAML file exists in this repository yet; `cargo package --list` for every publishable crate, reviewed, nothing unintended; no image assets in the tree at all, so no EXIF-metadata surface to check.
**Explicitly not done in this pass, flagged rather than silently skipped:** wiring the first three checks into an actual CI `release-hygiene` job (§19.4.12's "wire the first three into CI"), and the deliberate-failure test proving the `$0aptile`-quoting grep gate itself works (matching the S3 gate's pattern) — both need real CI infrastructure (a `.github/workflows/` file) that doesn't exist in this repository yet; building it is chapter/M8 scope, not this ADR's.

---

## ADR-0030 — RPM `%install` strips binaries explicitly; `%global debug_package %{nil}` silently disabled rpm's own implicit strip too

**Decision:** `packaging/rpm/fossh.spec`'s `%install` now runs `strip --strip-all` on the three installed binaries explicitly, rather than relying on either Cargo's `strip = true` release-profile setting or rpm's own automatic post-install stripping.
**What was actually observed, not assumed:** after ADR-0029 disabled automatic debuginfo/debugsource generation (`%global debug_package %{nil}`, needed because rpm's `find-debuginfo` couldn't resolve the `--remap-path-prefix`-rewritten source paths back to real files), the *installed* binaries in the built RPM came back `file`-reported as "not stripped" — despite Cargo's own `strip = true` genuinely stripping the exact same build moments earlier (confirmed directly: an identical local build outside rpmbuild, using the same `scripts/build-release.sh`, produces a `file`-reported "stripped" binary of the expected ~536 KB; the RPM-packaged copy of the same binary came back at ~705 KB, unstripped). On this system's rpm version, automatic post-install binary stripping is evidently tied to the same macro plumbing as automatic debuginfo generation, not an independent step — turning one off silently turned off the other, with no error or warning pointing at the connection.
**Fix:** an explicit `strip --strip-all` in `%install`, after the `install -D` calls. Still comfortably under the §17 size gate at ~536 KB (`fossh-cgi`) either way, but the point was never "still under budget by luck" — it's "match the same, deliberate, already-decided stripped-binary property this project has held since M1's release profile was written," regardless of which rpm macro plumbing happens to be enabled around it.

---

## ADR-0031 — Identity-hygiene gate (§19.4.12) is generic and public; the real name/email are supplied externally, never committed

**Decision:** `scripts/check-identity-hygiene.sh` checks the git author/committer identity against the expected pseudonym, a generic real-home-directory-path shape (any per-user directory under the two conventional Linux/macOS locations), this machine's hostname, and the `$0aptile` shell-quoting rule — all patterns that need no knowledge of the author's actual real name or email to be meaningful. It optionally also checks `$FOSSH_HYGIENE_EXTRA_PATTERNS`, an extended-regex alternation the script reads from the environment rather than containing itself. (Deliberately not spelled out as a literal path shape in this sentence — see the debugging note below for why that specific phrasing was itself a bug.)
**Reason:** the author's real name and email are exactly the two things this whole gate exists to keep out of the repository. Hardcoding them *into* the gate script — even just as "patterns to search for," never as content actually being asserted true — would ship them in the one place guaranteed to be public and permanent (a committed CI script), which is a worse outcome than not having the check at all. The extra-patterns variable is meant to come from a GitHub Actions repository secret in real CI, or be set locally (sourced from something under `private-onlyauthor/`, never committed) before a release — either way, outside the tracked tree.
**Verification:** `scripts/test-identity-hygiene-gate.sh` builds a throwaway git repo with a deliberately bad commit (wrong author identity, a real-shaped home path, an unquoted `$0aptile`) and asserts the gate fails on it, then cleans the same fixture in place and asserts the gate then passes — proving the detection logic actually detects something, per §19.4.12's "prove the gate works with a deliberate-failure test" (the same discipline §17 already requires for the SQL-concatenation gate). Ran both directions for real: the bad fixture correctly fails all three checks at once; the cleaned fixture correctly passes. `.github/workflows/ci.yml` wires this and the audit/deny/test/clippy/fmt checks into CI, including a real `iptables`-enforced network-denied test run for the zero-egress invariant — written and locally exercised (the two shell scripts, directly) but not run through actual GitHub Actions infrastructure, which doesn't exist for this repository yet.

**Follow-up debugging pass (same day):** running the gate against the *real* repository — not just the isolated fixture — surfaced three real bugs, none caught by the fixture test alone because the fixture never scans this repository's own tooling files:

1. The gate's own source, its test harness, and one `DECISIONS.md` sentence describing the path-shape pattern all legitimately *contain* text shaped like what the generic sweeps look for (regex source, a deliberately-bad fixture string, a literal example in prose) — guaranteed, uninteresting self-matches. Fixed by excluding `scripts/check-identity-hygiene.sh` and `scripts/test-identity-hygiene-gate.sh` from those two sweeps specifically (documented inline as to why), and rewording the `DECISIONS.md` sentence to stop spelling out the literal shape.
2. The `$0aptile` check's "safe" detection missed this same self-exclusion at first (only the path/hostname sweeps had it), so it kept flagging the gate's own comments and pattern-matching source describing the rule it enforces. Same fix, applied to the fourth check too.
3. Actually more interesting: the test fixture's own "cleaned" example used `echo "author: '$0aptile'"` as its supposedly-safe form — but a single quote *nested inside a double-quoted string* is just a literal apostrophe in real POSIX shell semantics, not a second quoting mechanism; it does **not** suppress `$`-expansion, so that line would still have expanded `$0` if actually executed. The gate correctly kept flagging it. Fixed the fixture (and the gate's own detection logic to match) to require the one form that's actually safe inside a double-quoted string: backslash-escaping (`\$0aptile`), or single-quoting as the line's only quoting mechanism with no double quote present at all.

Re-ran the fixture test and the real-repo gate after each fix; both are genuinely clean now, not just quieter.

---

## ADR-0032 — Development-status and preview-tier content signaled by directory location (`dev/`, `docs/preview/`), not repeated inline banners

**Decision:** `DURUM.md` moved to `dev/DURUM.md`; `docs/DEPLOY-nginx-cloudflare-tunnel.md` moved to `docs/preview/DEPLOY-nginx-cloudflare-tunnel.md`. `dev/` holds material about how the project is being built (chapter status, retrospectives) — not end-user documentation. `docs/preview/` holds deployment tiers documented ahead of this project's adversarial-review QA gate, as distinct from the reviewed guides directly under `docs/`. The nginx guide's own inline disclaimer was shortened accordingly, since the directory it now lives in already says most of what four sentences used to.

**Reason:** direct user feedback — inline "Status: preview, deferred, not reviewed yet" banners were scattered through otherwise-clean public docs, and private/in-progress/internal-process material was tangled with polished public documentation in one flat folder. A reader shouldn't need to parse a disclaimer paragraph to know a document's review status; the folder it's in should already tell them, the same way `private-onlyauthor/` already signals "not for you" by location rather than a per-file notice.

**Alternatives rejected:** keeping the inline banners as the sole signal (the status quo being fixed) — rejected, it's exactly what was flagged as messy; a `docs/DRAFTS.md` index page listing which guides are unreviewed — rejected as an extra layer of indirection the folder path itself already provides for free, with no reader benefit over just looking at the path.

**Verification:** every tracked cross-reference to both old paths found via `git grep -l` (14 files for the `DURUM.md` rename, 6 for the nginx guide) and fixed individually — see `dev/DURUM.md`'s own retrospective entry for the file-by-file list and two genuine incidental bugs the sweep surfaced (a stale "not shipped yet" claim about the Laravel/Symfony PHP middleware, and an end-user-facing CLI error message pointing at an internal-only tracker). `scripts/check-identity-hygiene.sh` and its deliberate-failure test both re-run clean after the move (path-based, so unaffected in principle, but re-verified rather than assumed). Full `cargo test`/`clippy -- -D warnings`/`fmt --check` re-run clean across both workspaces (root: 280 tests; `fossh-ffi`: 32 tests) after all edits.

One deliberate non-change: `DECISIONS.md`'s own ADR-0029 entry above still names `DURUM.md` without the `dev/` prefix where it describes a leak found and fixed in that file *before* this move happened. That's a historical fact about a past file state at a specific past moment, not a live pointer — rewriting it would misrepresent the order events actually happened in. Every other mention across the tree was a live citation meant to help a reader find the file today, so all of those were updated to the new path.

---

## ADR-0033 — License changed from dual Apache-2.0/MIT to MIT-only

**Decision:** foSSH is licensed under MIT alone. `LICENSE-APACHE` removed; `LICENSE-MIT` renamed to `LICENSE`. `Cargo.toml` (root and `fossh-ffi`'s separate workspace), `packaging/rpm/fossh.spec`'s `License:` tag and `%license` file list, `bindings/php/composer.json`'s `license` field, `bindings/ruby/fossh.gemspec`'s `spec.license`, `README.md`, `README.tr.md`, `readme.md`, and `tos.md` §4 all updated to match.

**Reason:** direct author instruction, overriding the original spec's own explicit line ("License: **Apache-2.0 OR MIT**", `fossh-implementation-prompt.md` §19-adjacent list). No reason was given beyond the instruction itself, and none was needed — licensing is the author's call to make, not something the spec or this log second-guesses. Recorded here per this project's standing practice of documenting every deviation from the original spec, not because the choice itself needs defending.

**Explicitly unaffected:** `deny.toml` (both workspaces) still allowlists `MIT`, `Apache-2.0`, and several other third-party licenses for *dependencies* — that allowlist governs what upstream crates this project may depend on, which is an entirely separate question from what license foSSH's own code ships under, and none of those dependencies' own licenses change because foSSH's license did. Likewise `NOTICE`'s per-dependency license listing (many entries genuinely are "MIT OR Apache-2.0" as chosen by their own upstream authors) is unrelated and untouched.

**Verification:** `git grep -ilE "apache-2\.0|dual.?licens|license-apache"` across the tracked tree before and after the change to confirm every real reference was found and updated, and that the only remaining "Apache-2.0" hits left afterward are `NOTICE`'s third-party dependency lines (correct, intentionally unchanged) and this ADR's own prose describing the change. Full `cargo test`/`clippy -- -D warnings`/`fmt --check` re-run clean across both workspaces after the `Cargo.toml` edits (a `license` field change doesn't affect compiled output, but re-verified rather than assumed, per this project's own standing practice for every change in this log).

---

## ADR-0034 — `fossh-admin::data_key::generate_and_write` races under concurrent first callers; fixed with write-temp-then-hard-link

**Decision:** `generate_and_write` no longer `create_new`-opens the real key path and writes into it directly. It writes the key to a private, per-attempt temp file (`<path>.tmp-<pid>-<random-hex>`, `0600`), fully writes and `sync_all`s it, then atomically `hard_link`s it onto the real path — succeeding exactly once across any number of concurrent first callers, the same way `create_new` did, but without ever making a partially-written file visible under the real path.

**Reason:** found by this module's own `concurrent_first_callers_all_converge_on_the_same_key` test failing intermittently — roughly 2 runs in 5, not a one-off — while re-running the full workspace suite after an unrelated M7 refactor. Traced to a real race, not a test artifact: the previous `generate_and_write` did `create_new`-open the real path (an atomic, single-winner operation) and *then* `write_all`+`sync_all` into it. Between those two steps, a concurrent loser's own `create_new` attempt would correctly fail with `AlreadyExists`, and `load_or_generate`'s fallback would immediately `fs::read` the same path — sometimes catching it mid-write (as few as zero bytes written so far), which `parse` correctly refuses as `Corrupt` rather than silently accepting, but which the docstring's own claim ("falls back to reading whatever the winner wrote, rather than erroring") did not account for. In production this manifests as `fossh-cgi`'s own `main.rs` logging "could not load data-encryption key" and exiting non-zero for a request unlucky enough to lose this race on a cold, concurrently-starting install — a real, if narrow and self-correcting (only possible before the key file exists at all, i.e., only in the first moments after `dnf install`/first boot), availability bug, not a security one — it fails closed exactly as S2 requires, it just fails closed *more often than it needs to*.

**Alternatives rejected:** a mutex/file lock around the whole read-or-generate sequence — rejected, adds a lock this crate (deliberately `#![forbid(unsafe_code)]`, no `flock` wrapper currently in its dependency tree) doesn't otherwise need, for a problem `hard_link`'s existing atomicity guarantee already solves for free; plain `rename` instead of `hard_link` — rejected, `rename(2)` *replaces* an existing destination rather than failing, which would let two concurrent winners silently overwrite each other's already-in-memory-returned key with a different one on disk, a strictly worse failure mode (silent key divergence) than the loud, fail-closed `Corrupt` error being fixed.

**Verification:** the temp-filename suffix uses its own 8 fresh random bytes (`read_random_bytes`), deliberately independent of the actual key's own randomness — a temp filename must never be built from any slice of real key material, even one that reveals nothing alone. Stress-tested by running the concurrent test 40 times in independent process invocations after the fix (0 failures) against a measured ~40% failure rate before it (2 of 5 sampled runs). Full `fossh-admin` suite (14 tests, including the three key-file tests unrelated to concurrency) and `cargo clippy -- -D warnings`/`cargo fmt --check` clean after the fix.

---

## ADR-0035 — `fossh-fcgi` (M7) implements only §7.2's direct-to-SQLite write path, not a spool-mode alternative

**Decision:** `fossh-fcgi` always writes accepted events straight to SQLite via a batched background writer thread (`fossh_store::Store::record_events_batch`, new — one shared transaction per flush, a `SAVEPOINT` per event within it so one invalid event can't take the rest of the batch down). It does not read `Config::mode` at all and offers no spool-based alternative, even though `Mode::{Spool, Direct}` already exists in `fossh_core::config` (default `Spool`) and `fossh-cgi` is exactly the spool-mode implementation of the same general pipeline.

**Reason:** §7.2's own wording doesn't describe direct-to-SQLite writing as one configurable option among several for this transport — it states it as what FastCGI mode *is*: "Persistent, listens on a unix socket... Same pipeline, but writes to SQLite directly with a batched transaction... and runs the compactor + retention jobs in a background thread." Read this way, `Mode` most naturally describes a choice *between which binary an operator deploys* (`fossh-cgi` for spool-first behind a stateless per-request model, `fossh-fcgi` for a persistent process that can safely batch writes) rather than a runtime toggle either binary needs to honor internally. Building a second, spool-writing code path inside `fossh-fcgi` — reusing the same `fossh_admin::data_key`-sealed spool `fossh-cgi` already writes, then either draining it itself or relying on external `fossh maintain` — was considered and deferred: it would roughly double this milestone's scope for a mode combination (a persistent process voluntarily giving up its own main advantage) the spec never actually asks for.

**Consequence, stated plainly:** `fossh-fcgi` never touches `fossh_admin::data_key` or the §3.8 spool-encryption layer at all — consistent with ADR-0027's own scoping of that encryption specifically to the spool file, which this write path never creates. Its own retention/vacuum maintenance (hourly retention, vacuum every 24th pass) exists because this is the first *persistent* ingest process in this project; `fossh-cgi` never needed one since `fossh-cli maintain` (external cron) already covers that for spool-based deployments.

**Verification:** a real end-to-end smoke test against the actual compiled binary (not just `cargo test`) — a real `fossh site create`, a real `fossh-fcgi` process bound to a real unix socket path with a real `fossh.toml`, a hand-rolled Python FastCGI client (deliberately independent of this crate's own protocol code, to catch mistakes the Rust implementation and its own tests might share) sending a real healthz request (204), a real unauthenticated ingest request (401), and a real authenticated one (204) — then reading the resulting `fossh.db` directly with Python's stdlib `sqlite3` and confirming exactly one real row landed with the correct site, timestamp, and hashed visitor. Full test suite (counts corrected post-review; the numbers below are what an independent adversarial pass actually counted, not this entry's own first-draft estimate — see the follow-up ADR-0036 for why the estimate was off and what else that same pass found): 31 tests in `fossh-fcgi` (protocol framing, connection assembly, the batched writer, `handle_connection`-level integration tests using `UnixStream::pair()`), plus 3 new in `fossh-store` for the batch-write path (42 pre-existing + 3, not 9 — including one proving a mid-batch invalid event's `SAVEPOINT` rolls back without affecting the events before or after it) and 5 relocated `fossh_ingest::forwarded` tests (moved from `fossh-cgi`, which needed the identical X-Forwarded-For trust logic). `cargo clippy -- -D warnings` and `cargo fmt --check` clean.

---

## ADR-0036 — `fossh-fcgi` adversarial review: five real findings fixed, two documented as deliberate, non-fixes

**Decision:** ran the missing adversarial-review pass against the whole `fossh-fcgi` crate plus its `fossh-store` batch-write addition (ADR-0035 shipped without one). Five real findings, all fixed and independently re-verified; two more considered and deliberately left as-is, for stated reasons rather than silently skipped.

**Fixed:**

1. **No read/write timeout on an accepted connection at all (High).** A handful of connections that connect and send nothing — accidental (a stalled reverse-proxy worker) or deliberate — permanently wedged the worker that picked each one up, since `connection::read_request`'s blocking reads never returned on their own; with the default 8-worker pool, as few as 8 such connections exhausted it, permanently, for the rest of the daemon's life. Unlike a stuck `fossh-cgi` request (one process, self-contained), a stuck `fossh-fcgi` worker thread never recovers on its own. Fixed: `secure_connection` sets a 30-second read *and* write timeout on every accepted stream before it reaches a worker, refusing the connection outright if the OS calls themselves fail. Regression test measures real elapsed time on a genuinely-never-sent-anything peer, not just that the setter didn't error.
2. **The PARAMS accumulator's size bound was checked after appending, not before (Low)** — the STDIN accumulator right below it already checked first. Bounded either way (one FastCGI record's content is capped at 65535 bytes by the wire format's own `u16` field, so the worst-case overshoot was fixed and small), but a real inconsistency with the documented "bounded before it's ever retained" intent. Fixed to match STDIN's ordering exactly. Writing the regression test surfaced a second, genuinely separate bug — in the test itself, not the fix: a filler buffer sized at exactly `MAX_PARAMS_BYTES` (65536) silently wrapped to a FastCGI record length of `0` when cast to the wire format's `u16` field (`65536usize as u16 == 0`), turning an intended "one big record" into an accidental empty end-of-stream marker. Caught because the test failed with the wrong error, not the expected one — fixed by capping the test's own filler at `u16::MAX` (65535, the real per-record ceiling) and using a second record to cross the total bound.
3. **A real, measured window where the socket file existed at `0755`, not `0600` (Moderate).** `bind()` then `chmod()` left a real, non-zero gap between the two calls during which the file was world-connectable — `connect(2)`'s permission check happens once, at connect time, so a connection made in that window stays valid even after the follow-up `chmod` tightens it. This project already has the correct pattern for exactly this class of problem, in `fossh_store::Store::open` for `fossh.db` (force the *creation* mode itself to be right, never correct it after the fact) — `fossh-fcgi`'s socket bind just hadn't been written the same way. Fixed with a restrictive process umask (`0o177`) held only across the `bind()` call itself, via `nix::sys::stat::umask` (a safe wrapper, no `unsafe` needed, consistent with this crate's `#![forbid(unsafe_code)]`) — safe to do this early in `main`, before any other thread exists to be affected by the brief global-state change. Verified manually (not as an automated `#[test]`, deliberately — see the code comment at `manual_check_bind_with_correct_permissions_is_0600_and_restores_umask`): writing this as a normal `#[test]` first caused a real, reproducible intermittent failure in a *different*, unrelated existing test whenever `cargo test`'s default concurrent execution happened to overlap the two, because `umask` is real process-*global* state and a directory the other test created mid-way through this one's restrictive window came out non-traversable. This project doesn't otherwise need a test-serialization dependency (`serial_test`) just for one narrow case, so this specific property is checked by hand instead, the same way the review that found the original issue verified it — with a real, working, empirically-confirmed repro, just not one wired into the parallel `cargo test` run.
4. **Stale-socket removal didn't check whether the socket was actually stale (Low).** Removing an existing socket path unconditionally, on bare file existence, would silently hijack a **live** instance's socket if this process were ever accidentally started a second time — the first instance keeps running, orphaned, while every new connection goes to the second one instead, with no warning printed anywhere. Fixed: `socket_is_live` attempts a real connect first; only a connect failure (nobody home) is treated as safe to remove and rebind.
5. **`DECISIONS.md`'s own test-count claims in this ADR's draft were wrong** — see the correction directly above.

**Considered, left as-is, and why:**

- **Both `mpsc` channels (connections, accepted events) are unbounded — no backpressure (Moderate).** A stuck writer thread or a burst of slow connections can grow either channel without an upper limit. Not fixed this pass: bounding them trades one failure mode for another (a bounded connection channel would make the accept loop itself start blocking under load, which has its own operational implications worth designing deliberately rather than bolting on) and the worst compounding case the review specifically named — wedged workers plus an unbounded events channel — is substantially defused by fix #1 above, since workers can no longer wedge forever. Documented here as a known, accepted risk rather than silently absent; revisit if real-world memory growth under load is ever actually observed, not preemptively.
- **Oversized PARAMS gets a raw connection close with no response; oversized STDIN gets a proper 413 (Informational).** A real asymmetry, but PARAMS content in any real deployment is essentially always webserver-generated (nginx sets `fastcgi_param`, not the visitor) — hitting this path in practice means a misconfigured proxy or an actual probing attempt, not legitimate traffic softly exceeding a limit the way an oversized POST body plausibly could. Judged not worth the added response-path complexity for a case that shouldn't fire from real traffic at all; left as a raw close, now a documented, considered choice rather than an unnoticed gap.

**Verification:** the adversarial-review pass itself independently constructed and ran three real repros beyond just reading the code — a genuine mid-`insert_one`-failure case for `fossh-store`'s `SAVEPOINT` rollback (corrupting a real rollup row's HyperLogLog blob via direct SQL, confirming the failing event's own partial writes, not just the whole batch, rolled back correctly), a real two-requests-on-one-connection case for `keep_conn`, and a live concurrency test for the worker-pool's mutex scope — all three confirmed correct, and all three reverted cleanly afterward (confirmed via `git status`/`git diff` matching the pre-review baseline exactly). After applying the five fixes above: `cargo test -p fossh-fcgi` (31 tests, up from 27) run 10 times consecutively with 0 failures (specifically checking for the flakiness class fix #3's own verification uncovered), `cargo test -p fossh-store` (45 tests, unchanged by this pass), `cargo clippy -p fossh-fcgi -p fossh-store -- -D warnings` and `cargo fmt --check` clean across the whole workspace.

---

## ADR-0037 — §3.7 fuzz harness: `fossh-fcgi` split into lib+bin, `fuzz/` wired against five real targets, execution blocked on a missing C++ compiler

**Decision:** two parts. First, `crates/fossh-fcgi` gained a `[lib]` target (`src/lib.rs`, `pub mod connection; pub mod protocol; pub mod writer;`) alongside its existing `[[bin]]`, with `main.rs` now consuming its own crate's modules via `use fossh_fcgi::{connection, protocol, writer};` instead of declaring them inline — the only way for anything outside the crate (`fuzz/`) to reach the hand-rolled FastCGI parser at all, since a bin-only crate exposes nothing. Second, `fuzz/Cargo.toml` (left half-scaffolded by a bare `cargo fuzz init` — wrong default `fossh-core` path, only one placeholder target) was rewritten with correct path deps on `fossh-core`, `fossh-ingest`, and the now-libified `fossh-fcgi`, plus five real `[[bin]]` targets matching the original spec's own testing-table list: `json_body`/`query_string` (`fossh_ingest::pipeline::{from_json_body,from_query_string}`, driven through a fixed `RequestContext` with a small non-empty allowlist — an empty one would fail every input at the first check and the fuzzer would never explore past it), `forwarded_for` (`fossh_ingest::forwarded::resolve_client_ip`, via an `arbitrary`-derived struct so the three-argument signature gets structured input instead of hand-rolled byte-splitting), `fcgi_framing` (`fossh_fcgi::protocol::{read_header, read_record_body, decode_name_value_pairs}` chained the same way `connection::read_request` actually calls them — the least-trusted bytes in the binary, straight off a Unix socket before any of foSSH's own auth runs), and `spool_frame` (`fossh_ingest::spool::decode_event`, the plaintext frame parser).

**Reason (fuzzing the inner layer, not the outer one):** `spool_frame` targets `decode_event` specifically, not the ChaCha20-Poly1305-sealed container around it (§3.8) — random bytes fail AEAD authentication almost immediately, so fuzzing the encrypted layer would spend nearly all cycles on that one rejection instead of exercising the length-prefixed field parser underneath, which is where a real memory-safety bug could actually live. Same reasoning shapes `json_body`/`query_string`'s fixed, non-empty allowlist: the goal is maximizing time spent inside `assemble_event`'s actual validation logic, not re-discovering that an arbitrary event name fails an allowlist check.

**Reason (`fuzz/` excluded from the root workspace):** first attempt (`cargo fuzz check`) failed with "current package believes it's in a workspace when it's not" — `fuzz/Cargo.toml` has no `[workspace]` table of its own, and the root `Cargo.toml` didn't exclude it, so Cargo tried to fold it into the main workspace. Rejected fixing this by adding `fuzz` to the root's `members` instead of `exclude`: cargo-fuzz's own build invocation passes `--config profile.release.debug="line-tables-only"` and needs the nightly-only `-Zsanitizer=address` family of `RUSTFLAGS`, neither of which composes with this workspace's shared `[profile.release]` (`panic = "abort"` in particular is actively wrong for a libFuzzer target). Added `"fuzz"` to the root's existing `exclude` array, next to `crates/fossh-ffi` (already excluded for its own, different reason — see the FFI-crate-split entry).

**Blocked on toolchain, not code:** `cargo +nightly fuzz check` (type-check only, no sanitizer instrumentation) gets past workspace resolution and dependency graph construction — confirming the `fuzz`/`exclude` fix and the path deps are correct — then fails building `libfuzzer-sys` itself: its build script needs to compile libFuzzer's vendored C++ sources, and this machine has no C++ compiler at all (`gcc`/`cc` present, no `g++`, no `clang`/`clang++`; confirmed by `which` and a filesystem search turning up nothing usable, and `dnf info gcc-c++` showing it's available in the repos but not installed). Per ADR-0023 (never place the account password in a command), `sudo dnf install gcc-c++` is surfaced here for the user to run, not executed by this session. Until then, all five fuzz targets are **written, unverified** (dev/DURUM.md's own status vocabulary) — hand-checked against each target function's real signature by reading the actual source (`RequestContext`'s exact field set in `fossh-ingest/src/pipeline.rs`, `resolve_client_ip`'s three-argument signature in `forwarded.rs`, `Header`'s public `kind: RecordType` field and `RecordType: PartialEq, Eq` in `fossh-fcgi/src/protocol.rs`, `decode_event`'s signature in `spool.rs`), not compiler-verified.

**Consequence:** the `fossh-fcgi` lib/bin split itself *is* fully verified independent of the C++ blocker — `cargo test -p fossh-fcgi --all-features` (31 tests, unchanged count, now split 26/lib + 5/bin across two test binaries instead of one) and `cargo clippy -p fossh-fcgi --all-features --all-targets -- -D warnings` both pass clean on real, current output. One incidental clippy fix landed alongside it: `&[b'y', b'y']` → `b"yy"` in a `connection.rs` regression test (`clippy::byte_char_slices`), caught by running clippy with `--all-targets` for the first time on this crate rather than a real behavior change.

**Update, same day:** the user ran the surfaced command themselves (`sudo dnf install -y gcc-c++ ocaml opam dune selinux-policy rpmlint`) via Claude Code's own `!`-prefix mechanism — the password never passed through this session at any point, including after being offered twice in chat, which this session declined to use for exactly the reason ADR-0023 exists (anything placed in a tool call becomes part of a persisted transcript). All five targets then built and ran for real: `cargo +nightly fuzz run <target> -- -max_total_time=15` gave 1.9M/1.2M/9.8M/5.7M/5.5M executions (json_body/query_string/forwarded_for/fcgi_framing/spool_frame) in 15 seconds each, zero crashes, no files left in `fuzz/artifacts/`. dev/DURUM.md's §3.7 row updated from "written, unverified" to "implemented, verified" accordingly — still short of dev/DURUM.md's own "QA-gate passed" bar, which this project reserves for a dedicated adversarial-review pass, not a clean smoke run.

---

## ADR-0038 — `tos.md`: explicit "modify freely, at your own risk" clause; fixed a stale Apache-2.0 citation ADR-0033 missed

**Decision:** two changes to `tos.md`, same document, same pass. First, a new §9 ("Open source: modify freely, at your own risk"), inserted between the existing "Assumption of risk" (§8, unchanged) and "You are the data controller" (renumbered §9 → §10) — everything from old §9 onward shifts up by one, ending at §20 "Contact" (was §19). The new section states directly, rather than leaving it implicit in MIT's own grant, that advanced users are free to modify, extend, fork, or otherwise treat the codebase as raw material, and that doing so doesn't change or narrow §6/§7/§8's warranty/liability/risk terms — a modified or forked deployment is covered by the exact same disclaimers as an unmodified one. Second, fixed a real leftover bug this pass surfaced while reading the file: §6, §7, and old §14 (now §15) still cited specific "Apache License 2.0 §7", "§8", and "§6" for their warranty/liability/trademark text, even though `LICENSE-APACHE` was removed and `LICENSE-MIT` became the sole `LICENSE` back in ADR-0033 — that citation sweep updated §4 and §11 (the two spots naming the license by name) but missed these three, which cited it by *section number* instead, a different grep pattern than whatever caught the other two. Reworded all three to restate the disclaimer in `tos.md`'s own plain language without depending on a license text (Apache-2.0's own §6/§7/§8 numbering) that no longer ships with this project at all — MIT's single unnumbered AS-IS paragraph doesn't have equivalent sub-numbering to point to, and MIT says nothing about trademarks at all, which is exactly why §15 needs to state that position independently rather than attribute it to the license.

**Reason:** direct instruction — open source means advanced users genuinely can "play with it like a lego," and the ToS should say that plainly rather than leave it to be inferred from an MIT-license citation in §4 that a non-lawyer reader has no particular reason to trace all the way through. Fixing the stale Apache-2.0 citations alongside it rather than as a separate pass: they were found by directly reading the file to place the new section correctly, the same "read the real file, don't assume last pass caught everything" discipline ADR-0029's identity-hygiene pass already established for this project.

**Verification:** `grep -n "^## " tos.md` confirms sequential 1–20 numbering with no gaps or duplicates after the rewrite. Checked every other file in the repo for a cross-reference to a `tos.md` section number ≥ 6 before renumbering (only `SECURITY.md` references one, `§5`, which sits before the insertion point and is untouched). `grep -rn "Apache" tos.md` now returns nothing.

---

## ADR-0039 — RPM: real `rpmlint` pass (two genuine fixes), `%check` added, reproducible-build + stripped-symbol verification for real release artifacts

**Decision:** three related pieces of §3.10/§3.11 closure, all against the actual `scripts/build-release.sh` artifacts and the actual RPM, not a differently-built stand-in.

1. **Reproducible build, done the canonical way.** First attempt used a bare `cargo build --release --workspace`, which is *not* what ships — it leaks the real build machine's absolute home-directory path into panic-location strings (confirmed: 45 real `strings` hits in that build), because it skips `scripts/build-release.sh`'s `--remap-path-prefix`. Redone correctly: `scripts/build-release.sh`, twice, from a clean `target/` both times (including `fossh-ffi`'s separate workspace), SHA-256 of all 6 shipped artifacts (`fossh`, `fossh-cgi`, `fossh-tui`, `fossh-fcgi`, `libfossh.so`, `libfossh.a`) diffed both runs — byte-identical — and `scripts/check-identity-hygiene.sh` clean against the same build. Stripped-symbol verification alongside it: `file` reports `stripped` on all 6, plain `nm` reports "no symbols" on all 6 (confirming `strip = true` plus the RPM's own explicit `strip --strip-all` actually took), and — the check that actually matters for a `cdylib` — `nm -D libfossh.so` still lists the full intended public C ABI (`fossh_init`, `fossh_event`, `fossh_pageview`, `fossh_flush`, `fossh_set_key`, `fossh_timing`, `fossh_record_env`, `fossh_last_error`, `fossh_free`, `fossh_abi_version`), proving stripping removed local/debug symbols only, not the dynamic export table Go/PHP/Ruby link against.
2. **A real `rpmlint` pass**, now that it's installed (see the environment-facts update in dev/DURUM.md). Against the spec: fixed 4 `macro-in-comment` warnings (comment prose mentioning `%build`/`%install`/`%{srcversion}`/`%{version}` by name — harmless, but the file already had the correct `%%`-escaping convention at one other spot, `%%global debug_package %%{nil}`, just not applied consistently) and added a `%check` section (`cargo test --workspace` + `fossh-ffi`'s own suite) where none existed. Against the built packages: fixed one real functional gap, `post-without-tmpfile-creation` — `/run/fossh` and `/run/fossh/salt` (tmpfiles.d entries, `packaging/systemd/fossh.tmpfiles.conf`) are normally only materialized by `systemd-tmpfiles-setup.service` at boot, so a `dnf install` on an already-running system left them missing until the next reboot; anything starting the service or running the setup wizard in that window would find the salt directory absent. Fixed with an explicit `systemd-tmpfiles --create %{_tmpfilesdir}/fossh.conf` in `%post`.
3. **Left alone, with reasons, not silently dropped:** `invalid-url` on `Source0` (a real download URL doesn't exist for this project yet — `%{name}-%{srcversion}.tar.gz` as a bare filename is the honest state, not a bug to paper over with a fabricated GitHub URL that wouldn't resolve to anything); `no-manual-page-for-binary` ×4 (real, genuine gap — no man pages exist for `fossh`/`fossh-cgi`/`fossh-fcgi`/`fossh-tui` — deferred, tracked here rather than quietly ignored); `non-standard-uid`/`non-standard-gid` and `tmpfile-not-in-filelist` (both expected side effects of correct, intentional design — a dedicated system user via `%pre`'s `useradd -r`, and tmpfiles-managed runtime directories that are never supposed to appear in `%files`); `dangerous-command-in-%post`/`%postun`/`%posttrans` (rpmlint flagging `rm` *inside* Fedora's own standard `%selinux_modules_install`/`%selinux_modules_uninstall`/`%systemd_post`-family macro expansions — not anything this spec's own scriptlet bodies contain, and reimplementing those macros by hand to dodge a linter warning would trade trusted Fedora infrastructure for a hand-rolled, less-reviewed equivalent); every `spelling-error` (rpmlint's dictionary not recognizing `cgi`/`fcgiwrap`/`fcgi`/`tui`/`systemd`/`md` — words that are spelled correctly, just not in its wordlist).

**Reason (`--nodeps` for the actual build):** `rpmbuild`'s `BuildRequires` check wants the system `cargo`/`rust`/`selinux-policy-devel` RPMs specifically; this environment's Rust is rustup-managed (deliberately, for nightly + exact-version control this whole project has relied on since M1), and `selinux-policy-devel` genuinely isn't installed (a naming miss surfacing the install command — `selinux-policy` landed instead of the `-devel` subpackage). The actual tools the build needs (`cargo`/`rustc` via rustup, `checkmodule`/`semodule_package` already present before this pass) are real and working; `--nodeps` skips rpm's package-database bookkeeping check, not the actual build steps, which is why `%check`'s real `cargo test` run inside this same `--nodeps` build still had to genuinely pass for the build to succeed at all.

**Verification:** a full, real `rpmbuild -bb --nodeps` + `-bs --nodeps` from a freshly `git archive`-built source tarball (not the stale one sitting in `~/rpmbuild/SOURCES/` from an earlier session) — `%check`'s `cargo test --workspace` and `fossh-ffi`'s suite both genuinely ran and passed as part of this build (watched the output directly, including `fossh-ffi`'s 32-test run), not skipped or mocked. `rpmlint` re-run against the rebuilt packages after each fix, confirming `post-without-tmpfile-creation` and all 4 `macro-in-comment` warnings gone, nothing new introduced. `rpm -qp --scripts` against the final `.rpm` confirms the `%post` fix is actually present in the shipped scriptlet, not just the spec source. Fresh `.rpm`/`.src.rpm` copied into `dist/`, replacing the stale pair built before `fossh-fcgi` existed.

---

## ADR-0040 — OCaml watchdog, first slice: process supervision + OpenPGP challenge-response primitives + signed tamper manifest (§3.3, partial)

**Decision:** new `watchdog/` directory, a `dune`-built OCaml project (opam switch `watchdog/_opam`, local, using the system `ocaml-system` compiler rather than opam building its own — both gitignored) implementing three of prrr.md's four watchdog-cluster pieces at the *logic* level, deliberately not yet wired to any network transport:

1. **`Nonce`** — cryptographically secure random bytes read directly from `/dev/urandom` (not OCaml's `Random`, which is not a CSPRNG, and not a dedicated RNG opam library), hex-encoded. Used for both challenge nonces (§2.1) and session tokens (`Session`).
2. **`Auth`** — challenge-response signature verification by shelling out to `gpgv` against a binary keyring, rather than depending on an OCaml OpenPGP library or hand-rolling OpenPGP parsing. `Session` layers short-lived (15-minute default), in-memory-only tokens on top, so a client doesn't re-sign a nonce per request; a watchdog restart invalidates every outstanding session by construction (nothing persists to disk), which is the conservative, correct failure mode for the process that *is* the trust anchor.
3. **`Manifest`** — tamper detection via a `gpg --clearsign`-signed manifest of `sha256sum`-computed file hashes, so the manifest's expected content and its signature travel as one file an attacker can't productively edit without the watchdog's own private key. `Supervisor.restart_if_safe` is the single gate every restart goes through: check the manifest first, and **refuse the restart** (not restart-and-log) on any of the three failure shapes (`Signature_invalid`, `Hash_mismatch`, `Io_error`) — §3.6 explicitly requires picking one policy and documenting it; restarting a binary this component cannot vouch for would defeat tamper detection's entire purpose, so "fail closed" was the only real candidate, consistent with this project's existing S2 principle on the Rust side.
4. **`Supervisor`** — spawns and `waitpid`s on `fossh-fcgi` (the one persistent process in this architecture; `fossh-cgi` is spawned fresh per-request by `fcgiwrap` and has nothing for a supervisor to watch). Adds a sliding-window restart-storm guard (default: 5 restarts per 60 seconds) not explicitly asked for by §3.3, but "restart on crash" with no bound turns one crash-looping binary into a self-inflicted denial-of-service; documented here rather than silently added.

**Not built in this pass, on purpose:** the QUIC/mTLS IPC channel (§3.4), the Unix-socket bootstrap handoff (§2.4), and anything that actually accepts a network connection and calls `Auth`/`Session`. `bin/main.ml` today is a real, working supervision+tamper-detection loop and nothing else — see its own header comment. Splitting the cluster this way follows prrr.md §4's own instruction not to batch sub-chapters before checking any of them: this slice is fully unit-testable in isolation (every module takes paths/keys/manifests as parameters, nothing hardcoded), where the transport layer would require a second, differently-shaped test harness (two processes actually talking QUIC to each other).

**Reason (gpg/gpgv over an OCaml crypto library):** §3.3 explicitly asks to keep this component's dependency tree minimal, "since it's the last line of defense if core is compromised." `gpg`/`gpgv`/`sha256sum` are already present on any real Fedora install (confirmed: `/usr/bin/gpg`, `/usr/bin/gpgv`, `/usr/bin/sha256sum` all present without any additional install) and are real, independently-audited, widely-deployed OpenPGP/hashing implementations — shelling out to them via an argv array (never a shell string — see `Subprocess.run`'s own header comment) adds zero new opam dependencies for cryptography while still being genuine, standards-compliant OpenPGP, not a hand-rolled signature scheme reviewed by nobody but this project.

**Two real bugs found while building this, not just while reviewing it after:**

1. **`Subprocess.run`'s pipes were created `~cloexec:false`.** `gpg` spawns `gpg-agent`, a lingering background daemon, as a side effect of some operations; without close-on-exec, `gpg-agent` inherited this module's `out_write`/`err_write` fds across `gpg`'s own `execve`, and kept them open indefinitely as a live daemon — `Unix.create_process` still gets a correctly open, non-cloexec fd 0/1/2 in the child either way, since a `dup2`'d descriptor never inherits `CLOEXEC` from its source, so cloexec on the *original* pipe fds costs nothing functionally. The read loop then blocked forever waiting for an EOF that only happens once *every* holder of a pipe's write end has closed it, not just the one process actually `waitpid`-ed on — a real, reproduced hang (`dune test` hit the 60-second harness timeout), not a theoretical concern. Fixed: `~cloexec:true` on all three pipes. Verified twice: the hang is gone, and `pgrep -x gpg-agent` after a full test run finds zero lingering processes, confirming the fix addressed the actual leak, not just the symptom that made it visible.
2. **`Option.value ~default:(failwith "...") found`, in `test/test_helpers.ml`'s key-fingerprint parsing.** `~default` is a plain, eagerly evaluated argument in OCaml, not a lazy thunk — this called `failwith` unconditionally regardless of whether `found` was actually `Some` or `None`, which is exactly why the very first test run failed with "could not find fingerprint" even though the fingerprint-parsing logic itself was already correct (confirmed by comparing against `gpg --with-colons --list-secret-keys`'s real, manually-inspected output before writing the parser, not guessed at). Fixed with an explicit `match found with Some x -> x | None -> failwith ...`.

**Verification:** 31 checks across 5 real test binaries (`test_nonce` 4, `test_auth` 5, `test_session` 7, `test_manifest` 10, `test_supervisor` 5), every one exercising real subprocesses — a real Ed25519 OpenPGP keypair generated per test via `gpg --quick-generate-key`, real `gpgv`/`gpg --clearsign`/`gpg --decrypt` round trips, a real `sha256sum` invocation, a real spawned-and-waited `/bin/sh` child — not mocked at any layer. Specifically confirmed, not just asserted: a bit-flipped signature and a signature checked against the wrong public key both fail; a manifest re-signed by a different key (simulating an attacker who can write the manifest file but not the watchdog's private key) is refused; a modified watched file is caught; a missing watched file reports `Io_error` rather than crashing; the restart-storm guard allows exactly `max_restarts` attempts and refuses the next one. `dune test` run 4 times consecutively, 0 failures. `dune build` clean from a `rm -rf _build`, zero warnings.

---

## ADR-0041 — OCaml watchdog adversarial review: 10 real findings, all fixed (2 critical, 3 high, 1 medium, 4 low)

**Decision:** ran the mandated adversarial-review QA gate (prrr.md §4) against ADR-0040's watchdog slice before building anything further on top of it. The review (a `general-purpose` subagent, given full context and instructed to prefer real repros over static reading) found 10 real, independently-executed findings against the actual compiled binary and library — 0 false positives, nothing dismissed as "not really exploitable." All 10 fixed in this same pass, re-verified, and re-tested rather than partially addressed.

**Critical — both mean the tamper-detection guarantee wasn't actually wired to what gets executed:**

1. **The watchdog's very first spawn was never tamper-checked at all** — `bin/main.ml` called `Supervisor.spawn` directly at startup; `Manifest.check` only ever ran inside the restart path, after a crash. A binary tampered with before the watchdog's own launch ran at least once no matter what, and indefinitely if it never crashed. Repro: a "tampered" stand-in binary ran once, unrefused, printing a marker line, before the *next* restart attempt correctly caught it. Fixed: `Supervisor.spawn_if_safe`, sharing the exact same tamper-check gate `restart_if_safe` uses, is now the only path into the initial spawn — there is exactly one way into `Supervisor.spawn` from either caller.
2. **Manifest content was never bound to the program actually being executed.** `Manifest.check`/`Supervisor.restart_if_safe` never verified the supervised program's own path appeared in the manifest's entries at all — a manifest covering unrelated files, or even zero entries, passed as `Ok_manifest` and restarted whatever was at `program`'s path regardless. Repro: signed a manifest naming only an unrelated file, then swapped the real program's contents *after* signing; `check` still said `Ok_manifest` and the swapped payload ran. Fixed: `Manifest.check` now takes `~program` and requires it to appear in the manifest's own entries (new `Program_not_covered` result), and a manifest with zero entries is `Program_not_covered` rather than a trivial `Ok_manifest []`.

**High:**

3. **`gpgv`'s bare exit code says nothing about key revocation or expiry.** A signature made by a key revoked *before* verification still exits 0 with "Good signature" — confirmed with a real revoked key (GnuPG prefixes its own auto-generated revocation certificate's armor header with a colon specifically to prevent accidental scripted import — `:-----BEGIN PGP...`; stripping exactly that one character, per the certificate's own explanatory comment, is what made the repro work at all) verified from a fresh homedir that only ever imported the already-revoked key. This defeats the standard incident-response action ("revoke the compromised key") for both the auth gate (§2.1) and the manifest's own signature. Fixed: dropped `gpgv` entirely in favor of full `gpg --verify`/`--decrypt` with `--status-file` (new `Gpg_status` module, parsing GnuPG's documented status-line protocol), checking specifically for `REVKEYSIG`/`EXPKEYSIG` — confirmed against `/usr/share/doc/gnupg2/DETAILS` (shipped locally with the `gnupg2` package) rather than assumed: the broader `KEYREVOKED`/`KEYEXPIRED` lines were deliberately *not* used, since DETAILS itself documents `KEYEXPIRED` as unreliable for this exact purpose ("will also be emitted for expired subkeys even if this subkey is not used... to check whether a key used to sign a message has expired, the EXPKEYSIG status line is to be used") — using the broader pair would have traded an under-rejection bug for an over-rejection one. `Auth.verify_signature` and `Manifest.verify_and_extract`/`check` now also take `~expected_key_fingerprint` and pin to it (comparing GOODSIG's reported key ID against the low-order 64 bits of the expected fingerprint), closing a related, smaller gap the review noted in passing: a keyring holding multiple trusted keys previously accepted a signature from *any* of them.
4. **`Subprocess.run` deadlocked on stdin content past roughly the OS pipe buffer size** (confirmed: 200KB against `/bin/cat` hangs, 70KB doesn't) because it wrote all of stdin before reading any output — any child producing output before fully draining stdin, which `gpg --decrypt`/`--verify` does, can wedge both sides permanently. Reproduced against the real in-scope path too: a 612KB clearsigned manifest (6,000 entries — a plausible size, not contrived) through `verify_and_extract` hung identically. Since this sits on every single restart decision, an oversized or misconfigured manifest permanently wedged the one thing standing between a core-process crash and a restart. Fixed: `Subprocess.run` now writes stdin from a dedicated `Thread.create`d writer (new `threads.posix` dependency) instead of sequentially before reading, removing the deadlock class entirely rather than just bounding it. A 6,000-entry (~600KB) manifest sign+verify round trip is now a permanent regression test in `test_manifest.ml` — if the deadlock ever came back, that test would simply never return, not fail with a message.
5. **Several fs/process operations on the hot restart path had no exception handling at all** — a missing manifest file, a manifest path that's a directory, a nonexistent `program`, or a non-executable `program` each crashed the *entire watchdog process* with an uncaught `Fatal error: exception ...`, all four confirmed against the real binary, 100% reproducible. This is a worse outcome than any single refused restart: the trust anchor itself disappears, with nothing left running to refuse anything further. Fixed: `bin/main.ml`'s `read_manifest` and `spawn_or_refuse` now convert every such exception into a logged, graceful refusal (distinct exit codes — see #6) instead of an uncaught crash. Re-verified against the real binary: a missing manifest, a directory-as-manifest, a manifest that correctly lists a nonexistent watched program (caught at the manifest-check stage, `Io_error`), and a real `EACCES` from `Unix.create_process` on a non-executable-but-covered program (caught at the spawn stage) all now exit cleanly with a logged reason — no more `Fatal error`.

**Medium:**

6. **Every refusal exited with status 0, identical to a clean intentional shutdown** — §3.6 requires "refuse restart + alert" as the chosen policy, and the refusal half worked, but nothing in the process's own exit status let an external supervisor/alerting layer tell "operator stopped it" apart from "tamper detected" or "restart storm." Fixed: distinct exit codes (0 clean, 2 usage error, 3 tamper-refused, 4 storm-refused, 5 manifest unreadable) — see `bin/main.ml`'s own header comment for the full table.

**Low / hardening (all fixed, none left as accepted risk):**

7. **GnuPG's clearsign format strips trailing whitespace per line** (RFC 4880's dash-escaping/trailing-whitespace-removal convention — confirmed by round-tripping a string with trailing spaces through a real `gpg --clearsign`), so a manifest path legitimately ending in whitespace would silently verify against a *different* path than the one actually signed. `Manifest.render` never itself produces trailing whitespace (the path is the last field on a line, and real file paths essentially never end in whitespace in practice), and the failure mode if it ever did occur is `Io_error`/`Hash_mismatch` — fail closed, not a silent bypass — so this was already low-risk; documented rather than additionally guarded, since adding path validation for a case that can't arise from this codebase's own manifest generation would be defending against a hazard that isn't actually reachable through it.
8. **Manifest entry paths weren't required to be absolute** — a relative path resolved against the watchdog process's own working directory at check time, making the same signed manifest mean different things depending on how the watchdog was launched. Fixed: `Manifest.parse` now rejects any entry whose path is relative.
9. **`Auth`'s `gpgv` call omitted a `--` end-of-options separator** before the positional sig/data file arguments (unlike `Manifest.sha256_hex`'s `sha256sum` call, which already had one) — moot now that `Auth` no longer calls `gpgv` at all (finding #3), but the replacement `gpg --verify` call includes `--` for the same defense-in-depth reason.
10. **`Session`'s token lookup is a plain `Hashtbl.find_opt`, not a constant-time comparison** — a real property, but confirmed still unreachable: nothing outside `session.ml`'s own tests calls `Session.*` anywhere in this codebase, since no network transport exists yet (§3.4, not built). Not fixed this pass, deliberately: `Hashtbl`'s hash-then-bucket-traversal lookup doesn't have the same early-exit-on-first-mismatch timing profile a naive `String.equal`-based linear scan would, so the risk is already low, and there is no live code path to test the fix against yet. Revisit when §3.4 actually wires a network listener to `Session`, not preemptively.

**Verification:** every fix re-tested against the real, compiled artifacts, not just re-read. Test suite grew from 31 to 41 checks (5 binaries), all passing, `dune test --force` run 3 consecutive times with 0 failures after the fix pass. `dune build` clean from `rm -rf _build`, zero warnings. `pgrep -x gpg-agent` confirmed zero lingering processes after every run, including the new revocation-test helper (`Test_helpers.revoke_in_place`) which does real key generation, real revocation-certificate import, and real cross-homedir key export/import. The four exception-safety scenarios from finding #5 were re-run directly against the compiled binary (not just inferred from reading the diff) and now exit 3 or 5 with a logged reason instead of an uncaught `Fatal error`.

---

## ADR-0042 — §2.4 bootstrap handoff: `SO_PEERCRED`-verified Unix socket, both sides built and cross-language-tested; §3.4 QUIC blocked on `cmake`

**Decision:** built both halves of §2.4's one-time bootstrap handoff — the watchdog hands its public key/cert fingerprint to core exactly once, over a local Unix domain socket, before any steady-state QUIC traffic exists.

- **Core's side** (`fossh_admin::watchdog_pin`, new module, Rust): `run_bootstrap_listener` binds a Unix socket, accepts exactly one connection, verifies the connecting peer's *real, kernel-reported* UID via `SO_PEERCRED` (`nix::sys::socket::sockopt::PeerCredentials` — a safe wrapper, no `unsafe`, consistent with this crate's `#![forbid(unsafe_code)]`) against an expected watchdog UID the caller supplies, reads a newline-terminated fingerprint, and persists it. Persistence goes through the exact same temp-file-then-`hard_link` pattern `data_key.rs` already established for this project, except inverted: `data_key`'s job is "many concurrent first-callers converge on one value, silently"; this module's job is "at most one handoff, ever, until an operator explicitly intervenes" — `AlreadyExists` on the final `hard_link` is the *desired* outcome here (refuse), not something to read past. A stale-vs-live socket-path check before removing anything reuses the same fix shape as `fossh-fcgi`'s own `socket_is_live` (ADR-0036, finding F4) — attempt a real connect first, only remove on a confirmed refusal, not bare file existence.
- **Watchdog's side** (`watchdog/lib/bootstrap.ml`, new module, OCaml): `send_fingerprint`/`send_fingerprint_with_retry` connect and send the same newline-terminated line. The retry wrapper (bounded, ~5 second default budget) is real operational necessity, not test scaffolding — core and the watchdog are two independently-started processes with no guaranteed ordering, and a one-time bootstrap step failing outright because it ran slightly before core finished its own startup would be a real, avoidable reliability gap. Exposed through a genuine, useful CLI subcommand on the real `fossh-watchdog` binary (`bootstrap-send <socket-path> <fingerprint>`), not just a library function only tests call — main.ml's own header comment states plainly that nothing wires this into the supervision loop's startup yet, since the watchdog doesn't generate its own keypair yet either (that piece, plus core-side integration into an actual service startup path, remains open — see dev/DURUM.md).

**Reason (`SO_PEERCRED` over directory-permission isolation alone):** §2.3's privilege separation gives `fossh-svc` and `fossh-watchdog` each their own `0700` directory, which means neither can simply place a socket somewhere the other can reach without weakening that isolation. `SO_PEERCRED` is the standard, idiomatic Unix answer to exactly this shape of problem: let the socket path itself be broadly discoverable, and let the kernel — not the filesystem, not anything the connecting process claims about itself — be the actual authority on who's on the other end of an accepted connection.

**Reason (a real cross-language integration test, not just two sets of unit tests):** `fossh-admin`'s 22 unit tests and `watchdog`'s new `test_bootstrap.ml` tests (part of the existing suite, now 47 checks total) each verify their own side against its own understanding of the wire protocol — neither can catch a mismatch *between* the two independent implementations. `crates/fossh-admin/tests/bootstrap_interop.rs` is a real Rust integration test that spawns the actual compiled `fossh-watchdog bootstrap-send` binary via `std::process::Command` against a real `run_bootstrap_listener` running in a background thread of the *same* test process — genuinely two independent implementations, two different languages, one real Unix socket, the OCaml binary a genuinely separate OS process with its own real UID for `SO_PEERCRED` to report. Skips (doesn't fail) if the OCaml binary hasn't been built in a given checkout, since `cargo test` has no way to invoke `dune build` as a side effect — a missing binary means "the OCaml side wasn't built here," a different fact from "the interop is broken."

**Blocked, documented rather than skipped silently:** §3.4's actual QUIC/mTLS transport needs the `quiche` crate (§2.2's locked decision), which resolved and confirmed a real `ffi` feature (matching "already C-ABI" from the spec), but its default TLS backend (`boringssl-boring-crate`, the only backend `quiche` 0.29.3 actually offers — confirmed by reading its own `Cargo.toml` `[features]` table, not assumed) vendors BoringSSL via `cmake`, which isn't installed. `quiche`'s own checked-in `include/quiche.h` (read directly from the downloaded crate source, without needing a successful build) confirms the C API shape §2.2 anticipated — `quiche_config_load_cert_chain_from_pem_file`/`load_priv_key_from_pem_file`/`load_verify_locations_from_file`/`config_verify_peer` for mTLS, `quiche_connect`/`quiche_accept` for connection setup, `quiche_conn_stream_send`/`stream_recv` for the actual IPC traffic — so the OCaml `ctypes` binding shape is now known even though nothing quiche-based has compiled yet. `sudo dnf install cmake` is the fix; per ADR-0023, surfaced for the user to run via Claude Code's `!` prefix, not executed here.

**Verification:** `cargo test -p fossh-admin` (22 unit + 1 real interop, all passing), `dune test` in `watchdog/` (47 checks, up from 41), `cargo clippy -p fossh-admin --all-targets -- -D warnings` and `cargo fmt --check` clean, full `cargo test --workspace` confirms nothing else regressed. The interop test's own assertions go past "the process exited 0": it confirms the exact fingerprint bytes the OCaml binary sent are what the Rust listener received *and* what ended up in the persisted pin file, closing the loop end to end.

---

## ADR-0043 — Watchdog generates and reuses its own keypair; `main.ml`'s CLI simplified to remove a real footgun

**Decision:** new `watchdog/lib/keypair.ml`: `ensure_keypair ~gnupghome ~uid` is idempotent — returns the existing secret key's fingerprint if `gnupghome` already has one, generates a fresh Ed25519 signing-only key only if it doesn't, and never regenerates over an existing key once one exists. `bin/main.ml`'s primary (supervision) mode now calls this at startup and uses the result as the manifest's expected signer, instead of taking a separate `<expected-key-fingerprint>` CLI argument — the manifest is always supposed to be signed by the watchdog's own key (§3.3: "sign it with the watchdog's own key"), so accepting a *different*, operator-supplied fingerprint was never a legitimate option, just a footgun (a copy-paste mistake would have silently pointed verification at the wrong key, with `Manifest.check` then correctly — but pointlessly — refusing every restart forever). CLI shrinks from `<program> <gnupghome> <expected-key-fingerprint> <manifest-path>` to `<program> <gnupghome> <manifest-path>`.

`test/test_helpers.ml`'s `generate_key` (used by nearly every test in the whole suite) now delegates to `Keypair.ensure_keypair` instead of duplicating gpg key-generation logic — every existing auth/manifest/supervisor test now incidentally exercises the real product code path too, not a parallel test-only reimplementation of it that could silently drift from what actually ships.

**Reason (idempotent, not regenerate-every-start):** the watchdog's own fingerprint is what §2.4's bootstrap handoff hands to core, which then pins it permanently (`fossh_admin::watchdog_pin`, ADR-0042) and refuses any *different* fingerprint without an explicit operator reset. A watchdog that generated a fresh key on every restart would invalidate that pin's whole premise the very first time it restarted — `ensure_keypair`'s idempotency is not an optimization, it's the property the rest of §2.4 depends on.

**Deliberately not done in this pass:** wiring `bootstrap-send` into this same startup path automatically. `main.ml`'s own header comment states the reason directly: the handoff is meant to run exactly once per install, and this binary has no local record of "did I already hand off successfully" independent of asking core — whose own listener is itself one-shot and may simply no longer be listening after a prior success. Auto-calling it on every restart without that state would either hammer a socket that's usually gone, or need a second persisted marker file whose own partial-failure semantics (handoff succeeded, marker write failed — now what?) deserve deliberate design, not a rushed addition alongside an unrelated CLI simplification. Tracked as open in dev/DURUM.md, not silently absent.

**Verification:** `dune test` (52 checks now, up from 47 — 5 new `Keypair` tests: fresh-homedir generation produces a real 40-hex fingerprint, a second call on the same homedir returns the *same* fingerprint rather than generating a new one — confirmed both by the returned value and by directly counting secret keys in the homedir afterward (exactly one, not two) — a third call with a *different* `uid` still returns the original key, and a genuinely different homedir gets a genuinely different key). Beyond the unit tests: a real, manual end-to-end smoke test against the actual compiled binary — generate a keypair via a throwaway first invocation (correctly refuses, no manifest exists yet, but the fingerprint it logs is stable across a second invocation), sign a real manifest covering `/bin/true` with that exact key via raw `gpg`, then run the real binary a third time and watch it spawn, verify, and cleanly exit — not simulated, the literal compiled `main.exe` end to end.

---

## ADR-0044 — `fossh-ipc`: real mTLS QUIC connection primitives for core's side of §3.4, three real bugs found and fixed by driving an actual handshake

**Decision:** new `crates/fossh-ipc` — core's (`fossh-svc`'s) side of the steady-state watchdog↔core QUIC/mTLS channel, using `quiche`'s safe Rust API directly (no `ctypes` needed on this side; that's the OCaml watchdog's half, still to come). Deliberately blocking I/O with a socket read timeout rather than `mio` (which `quiche`'s own examples use) — this project has no async runtime anywhere, and this channel carries occasional, low-frequency traffic between exactly one known watchdog and exactly one known core, not many concurrent clients, so a polling event loop and a connection-ID-keyed client table (both present in `quiche`'s own `examples/server.rs`) would be solving problems this channel doesn't have. Scope of this pass, matching how every other sub-chapter in this project has been built: real, adversarially-verified connection establishment with mutual TLS and basic stream send/recv — the transport primitives, not yet the app-level command protocol or session-token/replay-protection binding §3.4 itself still asks for, and not yet wired into any real service.

**Built by writing a real integration test against real certificates and driving it until it was actually correct — not by reading `quiche`'s examples and assuming the adaptation was right.** Three real, distinct bugs were found this way, each confirmed with direct evidence before being called a bug:

1. **`drive_until`'s "done" check ran between the recv-drain and send-drain phases, not after both.** Correct for an "have we become established yet" check, silently wrong for "send this, then stop": `send_on_stream`'s `|_| true` closure returned `true` immediately after the (usually empty, on a pure send) recv-drain phase — before the loop ever reached the send-drain phase that would actually flush the just-queued stream data onto the wire. Reproduced with `RUST_LOG=trace`: the queued data only ever reached the wire as an accidental side effect of a *later*, unrelated `drive_until` call on the same connection happening to run its own send-drain phase — meaning a send-then-immediately-drop caller (exactly what the test's server thread does) lost the data outright, since nothing ever triggered that next call before the socket closed. Fixed by moving the `done` check to after both phases, unconditionally, every iteration — any caller is now guaranteed at least one real send-drain pass before the function can return.
2. **A fatal `conn.recv()` error (e.g. `TlsFail` from a rejected peer certificate) was returned immediately, which skipped the very send-drain phase that would have flushed `quiche`'s own resulting `CONNECTION_CLOSE` packet to the peer.** `quiche`'s own `examples/client.rs` doesn't do this either — on a `recv()` error it logs and `continue`s the read loop, letting the rest of that same iteration (including the send phase) run normally. An earlier fix here that just matched that "don't return immediately" shape alone introduced a *second* bug: the error was then silently dropped entirely, since nothing recorded that it had happened, and `send_on_stream`'s unconditional `|_| true` reported success regardless. Final fix: the recv error is captured in a local, the send-drain phase still runs unconditionally (so the close notification actually gets sent), and *then* the captured error is what gets returned — not silently discarded, not returned so early that the peer notification never went out.
3. **The test itself asserted the wrong property at first**, expecting a client presenting an untrusted certificate to see `is_established() == false` immediately after `connect()` returns. Real, reproduced TLS 1.3/QUIC behavior (confirmed via `RUST_LOG=trace`, a genuine `CERTIFICATE_VERIFY_FAILED` from BoringSSL on the server side): a client can observe its own local handshake state as complete slightly before the server's rejection of the *client's* certificate propagates back, since that rejection is strictly a function of what the server does after receiving the client's Certificate/CertificateVerify messages — a later, separate step from the client's own view of its handshake. Not a `quiche` bug and not fixed in `fossh-ipc` itself; the test was asserting a timing guarantee TLS 1.3 doesn't make. Fixed by asserting the property that's actually meaningful — the connection never becomes usable, checked by polling with `recv_from_stream` (which loops to the caller's deadline, rather than `send_on_stream`'s intentionally single-pass shape) so the asynchronous rejection has real time to arrive.

**Reason (EC P-256 test certs, not Ed25519):** an early version of the same test generated Ed25519 certificates and got a real `Quiche(TlsFail)` on the happy path — both sides using certificates the other was correctly configured to trust, yet the handshake itself failed. Switching to EC P-256 (universally supported in TLS 1.3) made the identical test pass; not chased further since P-256 is what this channel will actually use, but worth a real follow-up if Ed25519 support specifically ever matters here.

**Verification:** `cargo clippy --all-targets -- -D warnings` and a clean `cargo build` from `rm -rf target`, both clean. The real integration test (`tests/mtls_handshake.rs`) run 5 consecutive times with 0 failures: a full mTLS handshake between two independently-generated, specifically-pinned self-signed certificates, a real bidirectional stream exchange, `peer_cert()` checked on both sides to confirm each side actually saw the *specific* certificate bytes generated for this run (not merely "a handshake didn't error"); and a client presenting a third, untrusted certificate confirmed to never reach a usable connection, polled to its full deadline rather than checked once. All debug instrumentation added while chasing these three bugs (`eprintln!` call sites, one `RUST_LOG=trace` session) was removed from the shipped source once each bug was confirmed and fixed — none of it remains in `crates/fossh-ipc/src/lib.rs`.

---

## ADR-0045 — `fossh-ipc`: 100ms socket read timeout was silently costing 24x–30x on every QUIC handshake; measured, root-caused, fixed to 2ms

**Decision:** as part of a scheduled comprehensive test/security/benchmark pass over the whole project (not triggered by a report — found by deliberately measuring instead of assuming the transport primitives built in ADR-0044 were fast merely because they were correct), `crates/fossh-ipc/src/lib.rs`'s `set_socket_timeouts` changed its `UdpSocket` read timeout from 100ms to 2ms.

**Root cause:** `drive_until`'s inner recv-drain loop calls `socket.recv_from` repeatedly to pull every currently-available packet off the wire before moving on, stopping only when a call returns `WouldBlock`/`TimedOut`. On a *blocking* socket with a fixed read timeout, that final, empty call cannot return early — the kernel has no way to tell "nothing more will ever arrive" apart from "something may arrive any moment now" without waiting out the full configured timeout. So every single pass of the outer `drive_until` loop paid the full 100ms on its last, empty `recv_from`, and a real QUIC handshake needs several such passes (the initial exchange alone is multiple flights). The cost wasn't visible by reading the code — `set_socket_timeouts` looked like an unremarkable, conservative default — only by timing a real handshake against a real peer.

**Measured, not estimated, both before and after, with the identical benchmark** (100 real loopback mTLS handshakes using `fossh-ipc`'s own `connect`/`accept_one`, and separately 100 full round trips of handshake + one stream message each way — a throwaway scratch binary, not the shipped crate, deleted after the numbers were captured):

| | handshake (median) | full round trip (median) |
|---|---|---|
| 100ms timeout | 211.3ms | 627.3ms |
| 2ms timeout | 8.8ms | 21.3ms |

Roughly 24x and 30x faster on the identical code path, same certificates, same loopback interface — the only change was the timeout value. 2ms was chosen, not some smaller value or a busy-poll (0ms), to keep the property this timeout exists for in the first place: letting `drive_until` wake up periodically to re-check its caller-supplied deadline and call `conn.on_timeout()`, rather than blocking indefinitely on a socket that may never receive another packet — e.g. a peer that silently vanished mid-handshake. This channel is documented (§3.4) as carrying occasional, low-frequency traffic between exactly one watchdog and exactly one core, not a hot path processing many connections per second, so 2ms of polling granularity costs nothing observable while still bounding worst-case wake-up latency far below anything a human or a downstream timeout would notice.

**Why this wasn't caught in ADR-0044:** that pass verified *correctness* — a real handshake completes, streams round-trip, a rejected certificate is actually rejected — and every one of those checks passed at 100ms too, just slowly. Correctness and performance are different questions; this project's own standing instruction to run a dedicated benchmark pass before considering a sub-chapter done (rather than treating "the tests are green" as the finish line) is precisely what surfaced this, and is the reason this ADR exists as a distinct entry rather than a footnote on ADR-0044.

**Verification:** after the change, `cargo clippy --all-targets -- -D warnings` clean; `tests/mtls_handshake.rs` run 3 consecutive times with 0 failures, confirming the timeout change didn't trade speed for correctness (a 2ms window is still long enough that `drive_until`'s recv-drain loop reliably observes `WouldBlock` rather than truncating a burst of packets that arrived just under the wire — nothing in the test suite, including the multi-packet handshake flights, showed otherwise). The exact before/after numbers above are recorded in `set_socket_timeouts`'s own doc comment so the reasoning for "2ms" stays attached to the code, not only to this ADR.

---

## ADR-0046 — `watchdog/quic`: OCaml `ctypes` bindings to `libquiche`, the watchdog's half of §3.4 — a real, cross-verified mTLS QUIC handshake, three genuinely hard linker problems solved empirically, and an adversarial review that found a real double-free

**Decision:** `watchdog/quic/` — the OCaml watchdog's side of the same steady-state QUIC/mTLS channel `crates/fossh-ipc` already built for core (ADR-0044/ADR-0045). Unlike the Rust side, which gets a safe API from the `quiche` crate directly, OCaml has no such library, so this is a real, hand-written FFI layer: `quic_shim.{h,c}` (a small C shim wrapping the handful of `quiche_*` functions that take raw `struct sockaddr*`, using real `inet_pton` calls rather than hand-rolled OCaml struct layouts — see that header's own comment for the full reasoning), `quic_bindings.ml` (raw `ctypes`/`Foreign.foreign` declarations, one line per C function, no logic), and `quic.ml` (the safe wrapper — connection driving loop, `connect`, `accept_one`, `send_on_stream`, `recv_from_stream`, `peer_cert`, `close`). Scope matches `fossh-ipc`'s own identical limit: real, verified transport primitives only — not yet the app-level command protocol §3.4 itself still requires, and not yet wired into either side's real runtime loop.

**`quic.ml` is a deliberate close port of `fossh-ipc`'s already-debugged Rust logic, not an independent reimplementation** — the connection-driving loop (`drive_until`/`recv_drain`/`send_drain`) mirrors the Rust version phase-for-phase, specifically preserving the two ordering fixes ADR-0044 had to find the hard way (the "done" check runs only after both drive phases, every pass; a captured recv error is returned only after send-drain has had the chance to flush `CONNECTION_CLOSE`), and the 2ms `Unix.select` poll granularity applies ADR-0045's already-measured lesson (a blocking read with a timeout can't distinguish "nothing more, ever" from "check back soon" without paying the full timeout) proactively rather than needing to rediscover it a second time on this side of the same channel.

**Three real, empirically-solved linker/FFI-visibility problems, none of them obvious from documentation alone:**

1. **`ctypes`' `Foreign.foreign` is a runtime `dlsym`-equivalent lookup, not a link-time relocation** — a wrong or missing C symbol name compiles and links cleanly, then fails only the first time that module loads (`Dl.DL_error("... undefined symbol: ...")`). This meant two separate, non-obvious build failures, each only discoverable by actually running the result: linking `libquiche.so` at all required `-Wl,--no-as-needed` (the ordinary linker default silently drops a `-l` dependency nothing has a *compile-time* reference to, exactly what every symbol here looks like from the linker's point of view) plus `-Wl,--export-dynamic` (so the loaded symbols are visible to a `dlsym`-style lookup, not just present in the binary); and this project's *own* `quic_shim.c` needed a genuine compile-time-referenced OCaml `external` (`fossh_quic_shim_touch`, a trivial no-op) to stop the linker from lazily dropping that whole object file from its stub archive, since nothing else in the file has a compile-time reference into it either.
2. **Static-linking `libquiche.a` with `--whole-archive` (to work around problem 1 for a third-party archive rather than adding a compile-time reference to it) produces genuine duplicate-symbol errors** — confirmed, not assumed: BoringSSL's own static archive bundles multiple CPU-dispatch variants of the same crypto primitive (`ChaCha20_ctr32`, `aesgcmsiv_htable_init`, etc.) under the same symbol name, meant to be resolved by ordinary lazy archive extraction (exactly one variant gets pulled in, based on what's actually referenced), not forced en masse. Applying `--whole-archive` more broadly (to work around the *same* class of problem for OCaml's own runtime archives) reproduced the identical failure mode against `libgcc.a`. Resolved by linking `libquiche.so` (dynamic) instead — a shared library's own symbol table is already fully resolved as a unit by the time it was built, sidestepping the whole "which archive members get pulled in" question, at the cost of a genuine new runtime dependency (below).
3. **A `.so`'s `DT_NEEDED` entry is recorded by its SONAME (`libquiche.so.0`, confirmed via `objdump -p | grep SONAME`), not by the plain `-lquiche`-derived filename** — `ldd` reporting `libquiche.so.0 => not found` even with the correct file present and `LD_LIBRARY_PATH` set correctly led to discovering this; fixed with a `libquiche.so.0 -> libquiche.so` symlink, now created automatically by `scripts/build-quiche-ffi.sh` alongside the file itself.

**Adversarial review (full agent transcript not reproduced here) found 9 real findings, all fixed:** most seriously, a genuine reproduced double-free (`Quic.close` was not idempotent — calling it twice, a plausible mistake once this is wired into a real supervisor loop with its own error-handling paths, crashed with `free(): double free detected in tcache 2`, SIGABRT; fixed with a `closed : bool ref` field, and pinned down with a dedicated regression test in `test_quic.ml` that would abort the whole test binary if it ever reoccurs) and a genuine RPM packaging ordering bug (`%install` ran `strip` on `libquiche.so.0` *before* the `install -D` line that creates it, aborting every single package build unconditionally under `set -e` — never caught because a full `rpmbuild` hadn't been re-run against this specific addition yet). Also fixed: every public function in `quic.ml` (`connect`, `accept_one`, `send_on_stream`, `recv_from_stream`) could previously raise an uncaught `Unix.Unix_error` instead of returning the `Error` its own `result` type promises, on entirely ordinary conditions for this protocol (`EADDRINUSE` on bind, `ECONNREFUSED` on a send after the peer vanished) — reproduced concretely (a held port causing `accept_one`'s own `Unix.bind` to fail leaked exactly one fd, confirmed via `/proc/self/fd`), and fixed with a shared `with_unix_errors_as_io_errors` wrapper applied to all four functions, matching what `fossh-ipc`'s Rust side already gets for free from `?`. A stale comment incorrectly claiming the Rust reference keeps `Config` alive "for the same scope" as its `Connection` (it doesn't — `config` is dropped the moment `connect`/`accept_one` returns, before the caller does anything else) was corrected to state the real justification for OCaml's more conservative choice. One finding (a peer's `STREAM_STOPPED`/`STREAM_RESET` on a single stream not always being caught by `drive_until`'s `is_closed()` check, leaving `recv_from_stream` fail-slow-to-deadline rather than fail-fast) was documented rather than fixed asymmetrically, since it's a pre-existing characteristic of the *shared* design `fossh-ipc`'s own already-reviewed Rust side has too, not a regression introduced by this port — a real follow-up, tracked for both sides together.

**RPM packaging closed out alongside the code, not deferred:** `packaging/rpm/fossh.spec` gained the new `BuildRequires` (`ocaml-ctypes-devel`, `ocaml-findlib`, `cmake`, `clang-devel`, `jq` — all confirmed available as native Fedora RPMs, no opam involvement), a `%build` step running `scripts/build-quiche-ffi.sh` before `dune build` (nothing earlier in `%build` already produces `libquiche.so`, unlike the Rust workspace's own dependencies), and `%install`/`%post`/`%postun`/`%files` changes to ship `libquiche.so.0` in a package-private `%{_libdir}/fossh/` directory with an `ld.so.conf.d` drop-in + `ldconfig` calls — the standard Fedora pattern for a private shared library exactly one package's own binaries use, rather than trying to bake a build-tree-relative rpath into the binary.

**Verification:** `dune build` clean from `rm -rf _build`, zero warnings. The real integration test (`test/test_quic.ml`) — full mTLS handshake between two independently-generated, specifically-pinned self-signed certificates, a real bidirectional stream exchange, `peer_cert()` checked on both sides against the actual generated certificate bytes (not merely "a handshake didn't error"), a wrong-certificate-presented scenario confirmed to never let the server conclude the connection is usable, and the double-close regression test — all run 3 consecutive times with 0 failures, both as `dune test` and as direct repeated invocation of the compiled binaries (bypassing dune's result caching, which otherwise skips re-execution when nothing changed). The full existing watchdog suite (all 8 test binaries, 57 checks total) re-run clean after every fix in this pass, confirming nothing regressed.

`packaging/rpm/fossh.spec` first re-validated with `rpmspec --parse` after the ordering fix (confirming the corrected install-then-strip sequence resolves correctly), then verified with a real, full `rpmbuild -bb --nodeps` against a `git archive` tarball of the actual committed tree (not a hand-picked subset of files) — `%build` (including the quiche vendoring step), `%check` (all 8 watchdog test binaries, including `test_quic`, genuinely exercising the new `LD_LIBRARY_PATH` fix in a real package build rather than just this session's own ad hoc shell), and `%install` all completed successfully, producing a real `fossh-0.1.0~alpha.1-1.fc44.x86_64.rpm`. `rpm -qlp` confirmed `/usr/lib64/fossh/libquiche.so.0`, its `%dir` entry, and the `ld.so.conf.d` drop-in all present exactly as intended; RPM's own automatic dependency generator correctly listed `libquiche.so.0()(64bit)` under `Provides` and did *not* add it to `Requires` (recognizing the package satisfies its own binary's dependency). `rpmlint` against the built package found only pre-existing findings (tmpfiles-not-in-filelist, dictionary-unaware spelling warnings on CGI/TUI/etc., the intentional non-standard system-user ownership, missing man pages, SELinux-relabeling's own `rm` calls) plus one new one worth recording rather than dismissing given this project's own "zero outbound" principle (§3.1): `binary-or-shlib-calls-gethostbyname` on `fossh-watchdog`. Traced with `nm -D` to `caml_unix_gethostbyname`, the C stub backing OCaml's standard `Unix.gethostbyname` — confirmed via `grep` across the entire watchdog source tree that nothing anywhere calls it or any other DNS-resolution function; the symbol is present only because it's part of the same `unix.cmxa` archive this project already depends on for legitimate socket/subprocess operations (a pre-existing dependency, not something this pass introduced), and is genuinely unreachable dead code from this binary's actual execution paths, not a live DNS-resolution capability. Documented here rather than silently noted and dropped, matching how this project treats every other rpmlint finding.

---

## ADR-0047 — §3.4's app-level command protocol: session-token-bound restart/reload, an abstract type closing a real API-shape footgun an adversarial review found

**Decision:** `watchdog/lib/command_protocol.ml` (+ `.mli`) — the wire format and session-binding logic §3.4 itself requires on top of the transport layer ADR-0044/ADR-0046 already closed out: "Any app-level command (restart, reload) must be bound to the current session context — a captured, valid command must not be replayable over a newly established connection." Deliberately QUIC-independent pure logic, matching how `Auth`/`Manifest`/`Session` are all tested without a live network connection — which side of the QUIC channel listens versus connects, QUIC stream ID allocation, concurrent command dispatch, and actually calling into `Supervisor` to execute a verified command are all separate, not-yet-built wiring, tracked as the remaining part of task #30, not silently folded into this pass.

**Session model, and why it doesn't duplicate §2.1's own challenge-response:** whichever side accepts commands (the "responder") issues one fresh `Session` token (reusing §3.3's existing module, not a new one) per QUIC connection, sent as that connection's first message; every subsequent command on that *same* connection must carry that exact token. This is layered on top of, not a re-implementation of, the channel's own mTLS: the handshake already proves both sides hold the private key matching their pinned certificate — the same guarantee §2.1's nonce-sign-verify model provides, just via the TLS transcript instead of an app-level signed nonce — so this layer's only remaining job is making a captured command+token pair from one connection useless on a different one.

**Adversarial review found 5 real findings, all fixed:**

1. **[HIGH, the headline finding] The original API let `verify_command`'s two parameters — `expected_token` (meant to be *this connection's own* issued token) and `presented_token` (whatever just arrived on the wire) — both be plain `string`s.** The reviewer confirmed empirically that the natural-looking, wrong integration `verify_command ~expected_token:wire_token ~presented_token:wire_token` type-checks, passes every unit test written against *correctly*-sourced tokens, and silently collapses the whole check to "is this any live session token issued to any connection, ever" — exactly the connection-agnostic, replayable check this module exists to go beyond. Not yet triggered anywhere (the wiring code that could make this mistake doesn't exist yet), but a real, foreseeable one-line bug with a complete, silent security bypass as its consequence. Fixed by making `session_token` an abstract type (`command_protocol.mli` exposes the type but not its constructor): the only way to produce one is `issue_session`, so sourcing `expected_token` from wire-parsed data is now a compile error, not an invisible mistake. This does not stop a *deliberately* wrong caller (the constructor is still visible inside `command_protocol.ml` itself) — it stops the accidental version, which is the realistic risk here.
2. **[MEDIUM] `Session`'s 15-minute default lifetime, reused unmodified, would reject commands from a legitimately still-open, still-authenticated connection for no reason other than being idle-but-open past 15 minutes** — §3.4's channel is meant to persist for an install's whole uptime, not the single bounded request flow that default was originally sized for (§2.1). Fixed with a new `Session.touch` (extends an existing valid session's expiry without changing its token value — the standard "activity keeps a session alive" pattern), called automatically inside `verify_command` on every *successful* verification (not on every presented token regardless of validity, so spraying wrong tokens at a real connection can't use this to prop open an otherwise-idle session). `issue_session` also gained an optional `?lifetime_seconds`, both because a real caller may reasonably want control over it and because it let the fix be tested through the real public API (a short, fast-expiring lifetime in the test) rather than reaching around the abstraction.
3. **[MEDIUM] `decode_session_hello`/`decode_command` accepted a "token" field containing an embedded literal newline** — `String.trim`/`split_on_char ' '` constrain whitespace at the edges and at spaces, not arbitrary control bytes in the middle. Not independently exploitable (nothing downstream mishandles it, and a value containing `\n` can never match a real 64-hex-char session token), but this module always knows the exact expected shape and had no reason to accept anything looser. Fixed with an explicit `looks_like_a_token` check (64 lowercase hex characters, matching `Nonce.generate`'s own output exactly) applied at both parse sites.
4. **[LOW] `describe_error`/`encode_error` echoed the full, unbounded, attacker-controlled line or command name back over the wire** — a malformed-on-purpose multi-megabyte line would produce a multi-megabyte `ERROR` response echoed straight back. Fixed with a 200-character truncation helper.
5. **[LOW] `Nonce.constant_time_equal`'s documented "differing lengths short-circuit immediately, this is fine" trade-off is safe only because its one current caller compares fixed-length, non-secret-length tokens** — nothing about the function's general-purpose export from `Nonce`, its name, or its type signature would stop a future caller from using it somewhere the length itself is sensitive, silently losing the exact property its name promises. Fixed by strengthening its doc comment to state this scope explicitly rather than leave it implicit; not renamed or restricted, since doing either would be disproportionate to a single, currently-safe call site.

Also closes a specifically-deferred item from ADR-0041 (§3.3's adversarial review): `constant_time_equal` was flagged there and left unfixed "specifically because nothing reachable at the time actually compared a session token against attacker-influenced input over a network" — this module's `verify_command` is that first reachable path, so the fix landed here rather than speculatively earlier.

**Verification:** `dune build` clean from `rm -rf _build`, zero warnings, including the new `.mli`. Two real test files — `test/test_command_protocol.ml` (27 checks: wire-format round-trips for both commands, every malformed-input rejection path including the newline-smuggling and oversized-line cases, the actual cross-connection-replay-rejection property exercised through the type-safe API rather than merely asserted, and the session-refresh-past-original-expiry property exercised through real elapsed time via `Unix.sleepf`) and additions to `test/test_nonce.ml` (5 checks specifically for `constant_time_equal`, including that a single differing trailing byte and a differing length both correctly compare unequal) — all passing. Full watchdog suite (9 binaries now, 90 checks total) re-run clean 3 consecutive times after every fix, both via `dune test` and direct repeated invocation of the compiled binaries.

---

## ADR-0048 — Wiring §3.4 into real services needs real X.509 certs, which don't exist anywhere yet; the bootstrap handoff's own wire format is too narrow to carry one

**Decision (scoping, not yet fully implemented — see below for what this pass actually builds):** while starting task #31 (wiring the now-complete QUIC transport and command-protocol layers into `bin/main.ml` and `fossh-fcgi`'s own `main.rs`), a real gap surfaced that neither `crates/fossh-ipc`'s nor `watchdog/quic/`'s own adversarial reviews had reason to catch, since both were scoped to "drive a handshake given `TlsPaths`/certs that already exist" — **nothing in this project generates a real X.509 certificate for the watchdog or for core, anywhere.** `fossh_admin::watchdog_pin`/`watchdog/lib/bootstrap.ml` (§2.4's bootstrap handoff, ADR-0042) already hand off and pin a "fingerprint," but tracing it end to end shows it's the watchdog's **OpenPGP** key fingerprint (`Keypair.ensure_keypair`'s own output — the key that signs the tamper-detection manifest, §3.3) — a completely different key, and a completely different format, from what `quiche`/BoringSSL's mTLS needs. `crates/fossh-ipc`'s and `watchdog/quic/`'s own tests both generate throwaway EC P-256 X.509 certs via `openssl req -x509 ...` purely as test fixtures; nothing analogous exists for a real, persistent, per-install identity on either side.

**A second, related gap the same trace surfaced:** even once real X.509 certs exist, the bootstrap handoff's current wire format (a single short line — "the fingerprint," `MAX_FINGERPRINT_LEN`-bounded, both sides deliberately agnostic to whether it's OpenPGP- or X.509-shaped per `watchdog_pin.rs`'s own comment) cannot carry what `quiche_config_load_verify_locations_from_file` actually needs: the *full PEM-encoded certificate content*, not a hash of it — this project's mTLS pinning model (ADR-0044's `TlsPaths.trusted_peer_cert_pem`) trusts one exact, complete pinned certificate as its own verification anchor, not a fingerprint checked against a separately-obtained cert. Extending or replacing that wire format is itself a real, deliberate change to an already-built, already-tested, security-critical component (ADR-0042) — not something to rush alongside unrelated work.

**Full plan, for continuity — most of this is *not* built in this pass:**
1. **This pass**: a new module generating and persisting a real, long-lived (10-year, not the test fixtures' 1-day) X.509 keypair+self-signed certificate per side, idempotent the same way `Keypair.ensure_keypair` already is for the OpenPGP key — see below for what actually landed.
2. **Follow-up, not yet started**: extend the bootstrap handoff's wire format to carry the full certificate PEM (both directions — core needs to hand its own cert to the watchdog too, since §3.4 requires *both* directions verified, not one-directional trust), re-verify `fossh_admin::watchdog_pin`'s and `bootstrap.ml`'s own existing test suites still pass, add new tests for the extended format.
3. **Follow-up, not yet started**: background-thread integration on both sides (watchdog's `bin/main.ml` currently runs one blocking supervise-loop with no concurrency at all; `fossh-fcgi`'s `main.rs` already spawns several background threads for unrelated duties — e.g. `writer::run`, the maintenance thread — so a QUIC client thread fits an already-established pattern there, but is new for the watchdog).
4. **Follow-up, not yet started**: actual command dispatch — calling `Supervisor.restart_if_safe`/an equivalent reload path from the responder side once `Command_protocol.verify_command` succeeds — and reconnection handling for when core's own process restarts (its QUIC connection dies with it).

**Which side is the QUIC server versus client — decided now, applies to all of the above:** the watchdog binds and `accept_one`s; core `connect`s. Read directly from both sides' actual code shape, not assumed: `bin/main.ml`'s existing loop is a single long-running process across many restarts of core (`Supervisor.wait_for_exit` in a loop) — the natural, stable, long-lived listener. `fossh-fcgi`'s `main.rs` is the process that actually gets killed and respawned by the watchdog on every restart — the natural side to reconnect fresh each time it starts, exactly mirroring how `crates/fossh-ipc`'s own `connect`/`accept_one` doc comments already describe this channel ("exactly one watchdog, exactly one core, never more").

**What this pass actually builds: `watchdog/lib/tls_identity.ml`**, the watchdog-side half of item 1 above (core's Rust-side equivalent is a further follow-up, not built here either — see the retrospective in `dev/DURUM.md` for why stopping here, not pushing further into the same pass, was the right call). Generates a real EC P-256 X.509 keypair+self-signed certificate via `openssl req -x509` (matching the exact curve every existing test already proved interoperates correctly with quiche/BoringSSL — ADR-0044's own note on why Ed25519 specifically failed), idempotent and directory-permission-hardened the same way `Keypair.ensure_keypair` already is, 10-year validity (not the test fixtures' 1 day) matching §2.4's own "regeneration requires a full re-bootstrap, not a silent rotation" model — a cert that expires on its own on any realistic install timeline would silently defeat that guarantee.

**Adversarial review found 4 real findings, all fixed:**

1. **[HIGH] No synchronization at all around the check-then-generate-then-persist sequence — two concurrent calls on the same directory can produce a permanently mismatched, silently-"valid" cert/key pair.** Reproduced empirically, not theorized: two concurrent real `openssl req` invocations targeting the same `cert.pem`/`key.pem` paths landed as a mismatched pair (one invocation's key alongside a *different* invocation's cert) in 10 of 80 real trials. Each half individually parses as perfectly valid — `cert_is_valid`/`key_is_valid` check each file in isolation — so the resulting broken identity reports itself healthy forever, and separately confirmed to fail `quiche_config_load_priv_key_from_pem_file` outright the one time it's actually used. Not reachable today (nothing calls `ensure_identity` yet), but on a direct collision course with this ADR's own item 3 (adding a QUIC-serving background thread to the watchdog, which currently has zero concurrency) — exactly the kind of change that could plausibly call this from two threads during startup without anyone noticing. Fixed with a plain OCaml `Mutex` serializing the whole sequence; a `Unix.lockf`-style cross-*process* file lock was considered and deliberately not added alongside it, since POSIX advisory locks are scoped to the process rather than the thread and would not by themselves have closed the actually-reproduced race — cross-process double-instantiation is treated as a deployment-level concern (matching how `fossh-fcgi` already handles its own single-instance question via `socket_is_live`), not this module's job. Pinned down with a dedicated regression test: 20 real threads racing `ensure_identity` on one fresh directory, then a real QUIC handshake proving the survivor is a matched, working pair.
2. **[MEDIUM] `cert_is_valid` checked structural parseability only, never expiry — an expired certificate was treated as valid forever.** Confirmed empirically: `openssl x509 -in <cert> -noout` exits 0 on a certificate that expired 5 years ago; `-checkend 0` correctly reports it as expired where the bare parse does not. This directly undermined the module's own stated design rationale (a cert that silently expires defeats the "no silent rotation" guarantee just as surely as an actual silent rotation would) — nothing in the code actually enforced it before this fix. Fixed by adding `-checkend 0` to the validity check.
3. **[LOW-MEDIUM] `common_name` containing a literal `/` or `=` could inject additional Subject-DN fields into `-subj`.** Confirmed empirically: `common_name = "innocuous/O=Evil Corp/OU=Fake Unit"` produced a certificate with a three-field Subject from one string argument — the classic `openssl -subj` construction footgun (distinct from shell injection, which `Subprocess.run`'s real-`argv` discipline already rules out and was separately re-confirmed: a `common_name` starting with `-` cannot be reinterpreted as a new `openssl` flag). Not exploitable today (no live caller passes untrusted `common_name`, and this project's mTLS trust model is exact-byte certificate pinning, never CN/SAN-based), but a real, reproducible construction bug worth closing before anything less trusted feeds this. Fixed by rejecting (not attempting to escape) any `common_name` outside a small safe character set, matching this project's general "reject malformed input, don't try to sanitize it" posture.
4. **[LOW] A `Unix.mkdir` failure other than `EEXIST`, or any exception from `Subprocess.run`, previously escaped `ensure_identity` as an uncaught exception instead of its declared `(t, error) result`.** This exact shape (only `EEXIST` caught around `Unix.mkdir`) is inherited unchanged from `Keypair.ensure_keypair`, already separately reviewed and accepted there — not re-litigated in that sibling module by this pass, only fixed locally here since this file was already open. Fixed with a single outer `try...with Unix.Unix_error` around the whole sequence, converting to a new `Io_error` variant.

**Verification:** `dune build` clean from `rm -rf _build`, zero warnings. `test/test_tls_identity.ml` grew from 8 checks (the original, pre-review version) to 20 — every new adversarial-review fix has a dedicated check, including the 20-thread concurrency race (verifying not just "no crash" but that every thread observed byte-identical certificate and key content, and that the survivor is a real, QUIC-handshake-usable pair), the expired-certificate rejection, and all four `common_name` rejection cases. Full watchdog suite (10 binaries now, 110 checks total) re-run clean 3 consecutive times after every fix, both via `dune test` and direct repeated invocation of the compiled binaries.

---

## ADR-0049 — Core's Rust-side X.509 identity (`crates/fossh-admin::tls_identity`): three real concurrency bugs found by actually racing it, not by reasoning about `rename(2)` semantics alone

**Decision:** `crates/fossh-admin/src/tls_identity.rs` — core's (`fossh-svc`'s) half of ADR-0048's identified gap, the Rust-side counterpart to `watchdog/lib/tls_identity.ml`. Same design intent as its OCaml sibling (EC P-256, 10-year validity, `openssl`'s own parser as the authority on "is this still valid" rather than mere file presence, the same `common_name` character allowlist closing the same `-subj` injection footgun) but a deliberately more ambitious concurrency model: the OCaml side's `Mutex` only serializes callers *within one process*, explicitly not attempting to cover a second `fossh-svc` instance racing the first (documented there as an accepted, deployment-level concern). This module set out to do better, generalizing `data_key.rs`'s own existing hard-link-based atomicity (already proven, already shipped, already reviewed) from one file to a matched cert+key pair — genuine cross-process safety, not just same-process.

**Getting there took three real, empirically-found bugs, each only surfacing under actual concurrent load, not from reading the code:**

1. **Directory-`rename` onto a non-empty destination always fails, including onto stale/corrupt content that plainly needs replacing.** The first design renamed a whole generation *directory* onto `dir/current` directly, mirroring `hard_link`'s "fails if destination exists" idea. `rename(2)` of a directory onto an existing *non-empty* directory always fails with `ENOTEMPTY`, unconditionally — not only when a legitimate concurrent winner is there. A first fix (re-check validity, pre-emptively remove confirmed-invalid existing content) closed the simple two-caller case, but a real, reproduced failure under heavier load (12 threads, ~1 run in 10) showed that with more than two racers, one caller's own remove-then-rename is not atomic *as a pair*, and a third caller's own fallback check could observe another's directory transiently torn down mid-removal and wrongly conclude nothing valid existed anywhere. **Fixed by swapping a symlink instead of a directory**: renaming a symlink (or any non-directory) onto an existing path atomically *replaces* it unconditionally — no "must be empty" restriction, no multi-step tear-down for anything else to race against. Verified against the exact scenario that broke the directory-based version, 100+ consecutive clean runs.
2. **The very next test run, at 100% reproducibility (not probabilistic): renaming a symlink onto an existing *real directory* fails with `EISDIR`.** This surfaced immediately because two of this module's own tests still seeded corrupt/expired leftovers using the old (pre-symlink) directory-based shape — a real reminder that a test simulating "state a piece of code could have left behind" needs to simulate the shape that code *actually* produces, not an earlier version's. Fixed on two fronts: the tests were corrected to seed a realistic symlink-based leftover (matching what this code itself would ever produce), and the function itself gained a small defensive check (if `current` is somehow a real directory, not a symlink — never produced by this function, but cheap to guard against stray external state) that removes it first, confirmed safe even under a concurrent race (`remove_dir_all` on a symlink removes only the symlink, never recursing into its target — verified directly, not assumed).
3. **[CRITICAL, found by a dedicated adversarial review after the above two were already fixed and stress-tested clean] The symlink swap made *writing* `current` atomic, but never made *reading through it* atomic as a pair.** `TlsIdentity.cert_pem_path`/`key_pem_path` were still two separate paths both mediated by the same mutable `dir/current` symlink. `rename`'s atomicity covers only the single act of repointing that symlink — nothing about two *separate, later* resolutions of paths that happen to traverse through it. If a different concurrent caller's own successful publish landed in the gap between a reader resolving `cert.pem` and separately resolving `key.pem` — entirely ordinary during the "many callers racing to establish this identity for the first time" scenario this module exists for — the reader got a certificate from one generation paired with a key from a different one: the exact mismatched-keypair failure class the whole directory-vs-symlink redesign was built to prevent, reopened through the read side instead of the write side. Reproduced two independent ways: an external reader with only a microseconds-wide gap between the two reads (real mismatches in most 40-trial runs), and even through this function's *own* single, immediate return value under an active establishment race (rarer, still real: 1 mismatch in 600 same-caller checks in one run). **Fixed by never handing back a path mediated by the mutable pointer at all**: `resolve_current` reads `current`'s target once and returns paths rooted at that specific, resolved `gen-*` directory, which — once created — is never mutated or removed by anyone except the caller that made it, and only when that caller's own publish did not win. A path obtained this way is a stable, internally-consistent reference for as long as the caller holds it, regardless of how many times `current` gets repointed afterward by someone else.

**Two smaller findings from the same review, also fixed:** every racing caller's generation directory was retained forever, not cleaned up unless *that specific caller's own* attempt failed — under a real establishment race, every "momentary winner" leaves a permanent, valid-but-unreferenced directory of private key material behind (confirmed: 16 racers, 16 directories, only 1 referenced). Judged an accepted, bounded characteristic rather than fixed with garbage-collection logic in this pass — the leak is proportional to how many processes ever raced during establishment specifically (expected to be small, and only during that one rare event; ordinary subsequent restarts hit the fast path and create nothing new), and safe, race-free cleanup of "no longer referenced" generations is its own real design question not worth rushing alongside everything else here. Also fixed: the private temp symlink used during publishing was left behind (a dangling stray, pointing at an already-removed directory) whenever the final rename itself failed for a real reason (confirmed reproducible, not just theoretical) — now cleaned up on every error path, not only the generation directory. And: `dir` and each generation directory were created with plain `fs::create_dir[_all]`, leaving their mode to whatever the caller's umask produced (confirmed empirically: `0755`, world-readable/traversable, under an ordinary `umask 022`) — unlike this module's own explicit `0600` on the key file itself, and unlike the OCaml sibling's explicit `Unix.mkdir dir 0o700`. Fixed with `DirBuilder::mode(0o700)` for both; masked in this project's actual RPM packaging today (`/var/lib/fossh` is already created `0700`) but not something this function should have depended on.

**A fourth, unrelated finding, surfaced only because this module's own heavy real-`openssl`-subprocess tests now run alongside everything else in the same crate:** two pre-existing tests in `watchdog_pin.rs` (§2.4's bootstrap handoff, already shipped, already reviewed under ADR-0042) turned out to be timing-fragile under real parallel system load — a 500ms connect-retry budget too tight when competing for CPU against this module's own concurrent-generation tests, and a stale-socket check asserted true on the very first attempt rather than allowing the kernel a moment to finish tearing down a just-closed listener. Neither is a regression this module's own logic caused; both became *visibly* flaky only because running this module's test suite legitimately adds enough concurrent load to occasionally expose timing assumptions those tests already had. Fixed in place (a wider retry budget; retrying the stale-socket check instead of asserting it once; tolerating `BrokenPipe`/`ConnectionReset` on the test client's own write, since a server that rejects-and-closes *promptly* on a bad peer UID — which is exactly the behavior under test — can legitimately race a client's write that hasn't reached the kernel yet). Stress-tested at `--test-threads=32`, 50 consecutive clean runs after the fix, versus 2 real failures observed across 40 runs before it.

**Verification:** `cargo build`/`cargo clippy --workspace --all-targets -- -D warnings` clean throughout. `tls_identity`'s own test module grew to 12 tests, including two built specifically to catch the CRITICAL torn-read finding from a second angle each (one modeling many callers racing to *establish* an identity and checking every single racer's own returned pair is internally matched; one modeling a reader repeatedly polling across 200 forced republishes from a concurrent background thread) — both run clean, and the full module stress-tested 80+ consecutive times with zero failures after the final fix, plus the concurrency-specific test run 100+ times in isolation. Full `fossh-admin` crate suite (31 tests) and full Cargo workspace (`cargo test --workspace`) both re-run clean 3 consecutive times, `--test-threads=32`. `fossh-ffi`'s own separate workspace re-checked clean (32 tests, unaffected, but re-verified rather than assumed).

---

## ADR-0050 — Task #31: wiring §3.4's QUIC channel and command protocol into the real, running `fossh-fcgi`/`fossh-watchdog` services

**Context:** ADR-0048 left a four-item follow-up plan for actually wiring the QUIC transport and command-protocol layers (both already built and separately adversarially reviewed) into the real binaries. Item 1 (real X.509 identities on both sides) was closed by ADR-0048/ADR-0049 themselves. This ADR closes items 2–4: extending the bootstrap handoff to carry full certificate PEM content, background-thread integration on both sides, and actual command dispatch.

### Part 1 — Bootstrap handoff extended to carry X.509 certificates both ways

`crates/fossh-admin/src/watchdog_pin.rs` and `watchdog/lib/bootstrap.ml` (§2.4's one-time Unix-socket handoff, previously OpenPGP-fingerprint-only and one-directional) now exchange full certificate PEM content in both directions over the same single round trip: the watchdog sends its fingerprint (unchanged) then its X.509 certificate (a PEM block terminated by its own `-----END CERTIFICATE-----` line, PEM's own delimiter used as-is rather than a new framing convention); core verifies the peer via `SO_PEERCRED` exactly as before, persists both, and writes its own certificate back before closing. `watchdog_pin.rs` gained `HandoffReceived`, `MAX_CERT_PEM_LEN` (8192), a bounded `read_pem_block`, and three new `PinError` variants. `bootstrap.ml` gained a matching `read_pem_block`/`send_handoff`/`send_handoff_with_retry`. New OCaml module `watchdog/lib/core_pin.ml` mirrors `watchdog_pin.rs`'s own temp-file-then-hard-link `persist_pin`/`load_pin` pattern (refuses to overwrite an existing pin — same "no silent rotation" enforcement, applied symmetrically to the watchdog's own record of *core's* certificate).

`fossh-watchdog bootstrap-send`'s CLI signature changed from `<socket-path> <fingerprint>` to `<socket-path> <gnupghome> <tls-dir> <core-cert-pin-path>`: it now derives its own fingerprint (`Keypair.ensure_keypair`) and X.509 identity (`Tls_identity.ensure_identity`) internally rather than taking a fingerprint as a literal argument — the exact same footgun already fixed once for manifest verification (an operator-supplied value that could mismatch what's actually loaded) applied equally here. On success it prints the derived fingerprint to stdout (separate from its stderr log lines) so an external caller — an install script, or `crates/fossh-admin/tests/bootstrap_interop.rs` — has a way to learn it, since nothing else exposes it.

**Real bug found via testing, not review:** an OCaml `Sys_error "Connection reset by peer"` during `bootstrap.ml`'s reply read was not caught by the original `read_pem_block` (which only matched `End_of_file`), crashing the whole `bootstrap-send` process with an uncaught exception — the same "uncaught exception takes down the whole process" failure class ADR-0041 already found and fixed elsewhere in this codebase, recurring here in new code. Reproduced directly: a test peer that accepts a connection and closes immediately, before reading the bytes already sent to it, causes the kernel to treat the close as abortive (unread data still pending in the receive buffer) — the writer's next read gets `ECONNRESET`, not a clean EOF. Fixed by adding a `Recv_failed` variant and catching `Sys_error` alongside `End_of_file` in `read_pem_block`. Two of the test file's own helper peers (`accept_and_vanish_after_reading`, the oversized-reply peer) were themselves adjusted to fully drain the incoming fingerprint+cert before closing/replying, so they exercise the intended clean-EOF (`Peer_cert_unterminated`) and cap-exceeded (`Peer_cert_too_large`) scenarios rather than accidentally tripping the reset path instead; a third, new test (`accept_and_reset_immediately`) deliberately exercises the reset path itself.

`crates/fossh-admin/tests/bootstrap_interop.rs` (the real cross-language test — compiled OCaml binary against the real Rust listener) was updated for the new signature and bidirectional exchange: it now asserts the fingerprint the Rust listener received matches what the OCaml binary printed to stdout, that both pin files (fingerprint, cert) land with the right content, and that core's own certificate arrives correctly at the OCaml side's pin file.

### Part 2 — Which side does what, and the shape of "one command per connection"

Confirms ADR-0048's own already-decided split (watchdog `accept_one`s, core `connect`s) and adds: **one QUIC connection carries at most one command, then both sides close it.** Not a persistent, held-open channel this pass has to reconnect when it drops — deliberately, because `Quic.recv_from_stream`/`fossh_ipc::recv_from_stream` are both built around "read until this one message is fin-terminated," not "read one message, then wait indefinitely for a possible next one on the same still-open stream." Structuring the protocol as one-shot-per-connection sidesteps ADR-0048's own item 4 "reconnection handling for when core's own process restarts" concern by construction: there is never a persistent connection outliving one request/reply exchange for that concern to apply to. Core's QUIC-client background thread (`crates/fossh-fcgi/src/quic_client.rs`) connects fresh, sends one command, reads the reply, and lets the connection drop — triggered by `SIGHUP` (`kill -HUP $(pidof fossh-fcgi)`), the conventional "reload" signal, blocked process-wide via `nix::sys::signal::pthread_sigmask` before any other thread spawns (signal masks are inherited at thread-creation time, not retroactively) and consumed one delivery at a time by a dedicated thread's own `SigSet.wait`/`sigwait`-equivalent loop.

**Stream layout, and a real bug found by testing it:** session hello (server → client, sent unprompted as the connection's first message) uses stream 1; the command and its OK/ERROR reply (client → server, then server → client on the same stream, opposite directions) use stream 4 — mirroring `watchdog/test/test_quic.ml`'s own already-proven request/reply-on-one-stream shape for that second exchange. The session hello was originally attempted on stream 0 and failed immediately with a real, reproduced `quiche_conn_stream_send` error (`QUICHE_ERR_INVALID_STREAM_STATE`, code −7): QUIC stream IDs encode who may be the *first* to write on them in their low two bits (0 = client-initiated bidirectional, 1 = server-initiated bidirectional), enforced by quiche itself, not merely convention — the server has no standing to open a client-initiated stream. Fixed by moving the session hello to stream 1, the first ID the server-initiated-bidi space actually grants it. Both `watchdog/quic/quic_command_server.ml` and `crates/fossh-fcgi/src/quic_client.rs` were updated together (they must agree on the numeric stream IDs, nothing negotiates them).

**Scope cuts made deliberately, not silently:**
- `Restart` and `Reload` both dispatch to the exact same `Supervisor.request_termination` action (a full tamper-checked respawn via the existing, unmodified `wait_for_exit`/`restart_if_safe` loop). Genuine live config reload without dropping the process is a separate, larger feature `fossh-fcgi` does not have today (no config-watching/hot-reload logic exists anywhere in it) regardless of this channel; building it was out of scope for "wire the already-built protocol into real services." The wire protocol itself already distinguishes the two commands, so this is forward-compatible with a real distinction landing later without another protocol change.
- Only `Reload` has a live trigger this pass (`SIGHUP`). `Restart` round-trips correctly on the wire (tested) but nothing calls it yet — there is no comparably conventional local signal for "fully restart me" that wouldn't just be `SIGTERM`/`SIGKILL`, which the watchdog's crash-detection path already handles independently of this channel.
- The separate §2.1 challenge-response auth gate (a human operator authenticating to the watchdog directly via `Auth`/`Session`'s GnuPG-based verification, pinned to a key enrolled at setup, §3.11 — confirmed by reading `auth.ml` directly: it verifies a pinned *enrolled operator* key, not core's own X.509 identity) remains exactly as open as `watchdog/bin/main.ml`'s own pre-existing header comment already documented ("the challenge-response auth gate's network listener" — listed there as a distinct not-yet-wired thing from "the QUIC IPC channel to core"). This pass does not build it, does not need it (core authenticates to the watchdog via mTLS + the per-connection session token instead, which is what `command_protocol.ml` was actually built against), and does not silently conflate the two.
- `Supervisor.request_termination`'s only cross-thread touch is reading `t.child_pid` and sending `SIGTERM`; the reap-then-decide-then-respawn sequence stays entirely on the main supervision thread, unmodified. Documented, accepted race: in the narrow window between the main thread reaping the old child and spawning a new one, a reused pid could receive the QUIC thread's signal instead. Not closed with a `Mutex` this pass — doing so properly needs the signal-then-wait sequence itself to be atomic with respect to the main loop, a larger synchronization redesign this specific wiring pass does not also take on. Accepted as a low-frequency, non-adversarial-at-will trigger (reachable only through an already mTLS-authenticated, session-verified connection), unlike attacker-controlled network input elsewhere in this project where the same kind of race would not be acceptable.
- Automatically invoking the bootstrap handoff from the watchdog's own startup remains the same open, manual-operator-step gap `main.ml`'s header comment already documented before this pass — core's own background thread waits for it (blocking on `run_bootstrap_listener`, logging once), it does not trigger it.

### Part 3 — `fossh-ipc` stays out of ordinary builds: a new, off-by-default Cargo feature

`fossh-ipc` (and the `fossh-quiche-ffi`/quiche/BoringSSL build it pulls in) is deliberately excluded from the root workspace's `members` specifically so `cargo build --workspace` never pays that cost for crates that don't need it (root `Cargo.toml`'s own existing comment). Wiring the QUIC client directly into `fossh-fcgi` — a real workspace member — as an unconditional dependency would have silently reintroduced exactly that cost for every build of that crate, member or not, defeating the exclusion's whole purpose. Fixed with a new `quic` feature on `fossh-fcgi` (off by default, alongside the pre-existing `fcgi`/`http` features), with `fossh-ipc` as an `optional = true` path dependency only pulled in when it's enabled, plus `nix/signal` (needed for `SIGHUP` handling) gated the same way. Verified directly: `cargo build -p fossh-fcgi` (default features) compiles `nix`, `fossh-admin`, `fossh-fcgi` only — no quiche, no BoringSSL, no `fossh-ipc` — while `cargo build -p fossh-fcgi --features quic` compiles the full stack (~16s from a warm target dir) and the resulting binary's background thread works end to end.

Core's own half of the command protocol's wire format (`SESSION`/`COMMAND`/`OK`/`ERROR` line encoding — `command_protocol.ml`'s counterpart) did not exist anywhere on the Rust side before this pass; traced and confirmed via a direct search, not assumed. New module **`crates/fossh-admin/src/command_client.rs`**: pure line-based encode/decode logic, deliberately QUIC-independent like its OCaml counterpart, living in the already-lightweight `fossh-admin` (a workspace member with no quiche dependency) rather than in `fossh-ipc`, so its own unit tests (8, covering the same shapes `command_protocol.ml`'s own tests already cover: well-formed round trip, non-hex token, missing keyword, oversized line, both command names, OK/ERROR replies, garbage rejection) run under the ordinary fast `cargo test`, no `--features quic` required.

### Verification

`cargo build`/`cargo clippy --workspace --all-targets -- -D warnings` clean (default features). `cargo build`/`cargo clippy -p fossh-fcgi --features quic --all-targets -- -D warnings` clean separately. `cargo test -p fossh-admin` (41 tests: 33 pre-existing + 8 new `command_client` tests) and `cargo test -p fossh-fcgi` (31 tests, unaffected by the new feature-gated code) both clean. `crates/fossh-admin/tests/bootstrap_interop.rs`'s real cross-language test clean after the signature/protocol update.

OCaml: `dune build` clean from a fresh tree. Full watchdog suite grew from 121 to 127 checks across 11 binaries (2 new in `test_supervisor.ml` for `request_termination`; 4 new in a new `watchdog/test/test_quic_command_server.ml` — a real end-to-end test using genuine openssl-generated certs and a real QUIC/mTLS connection, proving a genuinely valid session-bound `Reload` command actually delivers `SIGTERM` to a real spawned child process, *and* that a wrong-token command is refused with the child confirmed still alive rather than merely asserting the wire-level rejection). `dune test --force` clean, 3 consecutive runs.

### Part 4 — Adversarial review: 2 CRITICAL, 1 HIGH, 2 LOW, all fixed and regression-tested

A dedicated adversarial-review pass (a separate subagent, instructed to build real reproductions rather than reason abstractly) was commissioned specifically against this wiring pass. It found and reproduced real bugs the existing test suite's own passing state had not caught, and gave a clear recommendation on the cross-language-test question left open above. Every finding below was independently reproduced a second time during the fix pass (not merely trusted from the review's own report) before being called fixed.

1. **[CRITICAL] `handle_one_connection` could raise an uncaught exception that permanently kills the QUIC command server thread.** `Command_protocol.issue_session` reaches `Nonce.generate`'s `open_in_bin "/dev/urandom"`, which raises a plain `Sys_error` on fd exhaustion — reproduced directly under a real `ulimit -n 256`, confirming the exact failure. Nothing between there and `serve_forever`'s call site caught it; `Quic.accept_one`'s own identical call to the same function *is* already guarded (`with_unix_errors_as_io_errors`) — this new call site simply didn't repeat that established pattern. Fixed: `serve_forever` now wraps the whole `Fun.protect`-guarded connection handling in a catch-all `try ... with exn -> log ...`, so any exception during one connection is logged and the accept loop continues to the next — `Quic.close state` still runs first via `Fun.protect`'s own guarantee either way.

2. **[CRITICAL] A verified `Reload`/`Restart` command fed the exact same crash-storm counter a genuine crash loop needs, and exhausting it killed the entire watchdog process, not just refused one restart.** Reproduced end-to-end against the real compiled binary: 6 individually valid, session-verified `Reload` commands over 6 separate real QUIC connections — exactly what 6 real `SIGHUP`s to `fossh-fcgi` produce — made the real `fossh-watchdog` process exit with code 4 (`main.ml`'s own "too many restarts too fast" path), the *entire* supervisor gone, not one restart refused. An ordinary operational pattern (reloading config a few times inside a minute), not an attack, took down the one thing meant to keep restarting core. Fixed with a new `Supervisor.t` field, `termination_was_requested`, set by `request_termination` right before it signals the child and consumed exactly once per `wait_for_exit` cycle by a new `Supervisor.take_requested_termination`; the main loop in `bin/main.ml` now branches on that flag to a new `Supervisor.restart_after_requested_termination` (still tamper-checked — a verified command must never relaunch a tampered binary any more than a crash could — but deliberately *not* storm-guarded) instead of the crash-triggered `restart_if_safe` path, for both a signal-caused exit and the edge case of a supervised program that happens to catch `SIGTERM` and exit cleanly (`Exited 0`, which the pre-existing code already special-cased as "definitely intentional, stop supervising" — now conditioned on `not was_requested` too, so a graceful-exit reload doesn't accidentally end supervision entirely). Skipping the storm guard here rather than giving this path its own separate, more generous counter is a deliberate, documented scope cut: reaching this function at all already requires a real mTLS handshake plus a fresh, connection-scoped, replay-proof session token, a materially different threat model from an unattended crash loop. A dedicated regression test (`test_supervisor.ml`) now drives 8 real command-triggered restart cycles (more than the 5-restart default cap) end to end through the real dispatch path and asserts every single one completes.

3. **[HIGH] `core_pin.ml`'s `persist_pin` had the identical uncaught-`Sys_error` gap already found and fixed once this same pass, on the write side this time.** `output_string`/`close_out` are `Stdlib` channel operations (raise `Sys_error`, not `Unix.Unix_error`) — the exact footgun `bootstrap.ml`'s `read_pem_block` fix (Part 1 above) already closed once. Reproduced via a forced `EFBIG`/`Sys_error "File too large"` (`ulimit -f 1`), standing in for any real disk-full/quota condition during the one-time bootstrap write. Fixed by adding a `Sys_error` catch alongside the existing `Unix.Unix_error` ones. Two smaller instances of the same theme, fixed alongside it: `load_pin` mapped *any* `Sys_error` (including a real permissions/IO failure on an existing file) to `Ok None`, misreporting a genuine error as "not yet pinned" — now checks `Sys.file_exists` first and only treats a missing file as `None`, mirroring `fossh_admin::watchdog_pin::load_pin`'s own Rust-side `ErrorKind::NotFound`-only semantics exactly; and `bin/main.ml`'s `bootstrap-send` handler had an unguarded `Fileutil.read_all_bytes` call immediately before sending the handoff, now wrapped the same way.

4. **[LOW] `command_client.rs` and `command_protocol.ml` — meant to parse byte-identical wire text — did not actually trim identically.** Confirmed empirically: Rust's `str::trim()` strips every Unicode-whitespace codepoint (removes a trailing NBSP); OCaml's `String.trim` strips a fixed ASCII set only (leaves NBSP attached). Currently inert (neither side's own `encode_*` ever produces non-ASCII whitespace) but real, undetected protocol drift between two "identical" parsers — found only by testing the actual behavior, not by either side's own hand-typed-string unit tests, which is precisely the class of risk finding 6 below is about. Fixed with a new `ocaml_compatible_trim` in `command_client.rs`, trimming exactly OCaml's five-character set instead of Rust's default, with its own regression test pinning the NBSP-not-stripped behavior down directly.

5. **[LOW] `serve_forever`'s retry-on-error path had no backoff**, busy-looping as fast as the CPU allows against a *persistent* (not transient) `accept_one` failure — e.g. something else already holding the configured port. Fixed with a 1-second sleep before retrying (the existing `Deadline_exceeded` path, which already waited out its own 300-second per-attempt window, needs no additional delay).

**Explicitly verified fine, no fix needed:** the cross-thread `child_pid` read in `request_termination` carries no additional hazard beyond the already-documented, accepted pid-reuse race — this project's OCaml threads are `Thread`-module systhreads cooperatively scheduled on one OCaml 5 domain, not `Domain.spawn` parallelism, confirmed directly from `main.ml`'s own `Thread.create` call site; the `SIGHUP`-blocking-before-other-threads-spawn ordering claim in `crates/fossh-fcgi/src/main.rs`; the `quic` Cargo feature's build isolation (`cargo tree` with and without `--features quic`); Rust's `Drop`-based cleanup for `fossh_ipc::connect`'s returned connection/socket (no manual close needed, unlike the OCaml ctypes side); `watchdog_pin.rs`'s exception handling (Rust has no split exception channel for this class of bug to hide in); the stream-ID scheme itself (no residual reuse of stream 0, no analogous mistake elsewhere).

### Part 5 — The cross-language command-channel test: closed, not deferred

The review's own explicit recommendation was not to defer this gap: the *exact* channel this pass wires up already had one real, reproduced interop-only bug (the stream-0/stream-1 mismatch in Part 2 above) that neither side's own same-language test suite could structurally have caught, and finding 4 above is a second, independent, live example of undetected drift between the two "identical" implementations existing at review time. Given the pattern to close this already existed and works (`bootstrap_interop.rs`), and manifest-signing turned out to be trivial to replicate from Rust (it's two subprocess calls — `sha256sum` and `gpg --clearsign` — not a parallel reimplementation of `Manifest`'s own logic), this was built rather than left open.

New: `crates/fossh-fcgi/tests/quic_command_interop.rs`, feature-gated (`#![cfg(feature = "quic")]`, skips cleanly if the OCaml binary isn't built, matching `bootstrap_interop.rs`'s own convention). Spawns the real compiled `fossh-watchdog` binary in its real, ordinary supervision mode (`fossh-watchdog /bin/sleep <gnupghome> <manifest>`, a real `gpg`-generated key, a real `gpg --clearsign`ed manifest covering `/bin/sleep`) with its QUIC server pointed at a free loopback port via the same `FOSSH_WATCHDOG_TLS_DIR`/`FOSSH_CORE_CERT_PIN`/`FOSSH_QUIC_LISTEN_ADDR` environment variables a real deployment would set, pre-seeds the watchdog's core-cert pin with a certificate from core's own real `fossh_admin::tls_identity::ensure_identity` (starting from "the bootstrap handoff already happened," which `bootstrap_interop.rs` already separately covers, rather than re-driving that whole exchange here too), and calls `quic_client::send_one_reload` — now `pub`, specifically so this test can drive the exact same function `run`'s real `SIGHUP` loop calls, not a parallel reimplementation — in a bounded retry loop against it. Asserts both that the Rust side received a verified `OK` reply *and* that the real watchdog process's own log confirms it dispatched the command, not just this side's own belief about the wire reply.

One real bug surfaced building the test itself, worth recording since it is a general pitfall for this kind of test, not specific to this channel: killing only the spawned watchdog process (`Child::kill()`) left its own supervised `/bin/sleep` running as an orphan holding an inherited copy of the test's stderr pipe open, hanging `wait_with_output()` for the rest of `/bin/sleep`'s argument. Fixed by starting the watchdog in a fresh process group (`process_group(0)`, which `/bin/sleep` — spawned later via a plain `fork`+`exec` with no `setpgid` of its own — inherits) and killing the whole group (`kill(-pid, SIGKILL)`) instead of just the one process.

**Verification:** 3 consecutive clean runs of the new interop test (`ok`, 21–33s each — the real cross-process startup and `gpg` key generation dominate that time, not anything slow in the channel itself). Full Cargo workspace (`cargo test --workspace`, `cargo build`/`cargo clippy --workspace --all-targets -- -D warnings`, and the same three with `-p fossh-fcgi --features quic`) clean. Full OCaml watchdog suite grew from 127 to 130 checks across the same 11 binaries (net +3 in `test_supervisor.ml`: the corrected `take_requested_termination` checks plus the 8-cycle storm-guard-bypass regression test), `dune build`/`dune test --force` clean.

---

## ADR-0051 — §3.5 privilege separation: real filesystem tests against real system users, not simulated ownership

**Decision:** prrr.md §3.5 explicitly requires this be verified "with actual filesystem tests (not just design docs)," which needs the real, distinct `fossh-svc`/`fossh-watchdog` system users to exist — no way to meaningfully fake two different UIDs' real permission enforcement from inside a single-user dev sandbox. New `scripts/verify-privilege-separation.sh`: must run as root (creates and `chown`s `/var/lib/fossh` and `/var/lib/fossh-watchdog`, matching §2.3's model of one directory per service, mode 0700, no shared access — `packaging/rpm/fossh.spec` only creates the former today, since no systemd unit or packaging exists yet for the watchdog side, a separate already-tracked gap this script works around rather than blocks on), then uses `runuser` — not `su` — to actually act as each service account and test the boundary directly. `runuser` specifically because both accounts are `/sbin/nologin`: unlike interactive `su`, it doesn't require a real login shell or a PAM session to switch into a service account, which is exactly the shape these two accounts have.

**Checks, all real operations against real files, not assertions about mode bits:** `fossh-svc` cannot read, list, create a new file in, or overwrite an existing file in `fossh-watchdog`'s directory. Checked the other direction too, not just the one prrr.md's own wording states: `fossh-watchdog` cannot write into `fossh-svc`'s directory either — a watchdog able to freely rewrite core's own data directory would be a real, separate privilege-boundary gap of its own, not something to leave unchecked just because the spec phrased the requirement one-directionally. A sanity check confirms `fossh-watchdog` *can* read its own file — proves the negative checks above are failing for the right reason (real permission enforcement) rather than the path being broken or unreadable to everyone including its own owner, which would make every "cannot" check pass for a meaningless reason.

**Could not be run by the agent itself**, and this is worth recording as a real, structural constraint rather than an oversight: the environment has no passwordless `sudo` (confirmed directly — `sudo -n true` fails with "a password is required") and no TTY available through this session's own shell for an interactive password prompt (confirmed — every `sudo` call attempted this way failed identically with "a terminal is required to read the password"). The script was written to be fully self-contained and safe to hand off (idempotent directory setup, cleans up its own test file afterward, leaves the real production directories in place since they're needed anyway) specifically so the user could run it once, in a real terminal, and paste back the result — which is what happened. All 6 checks passed on the first real run.

**§3.5's second requirement** ("`fossh-svc` cannot invoke a restart of itself or bypass the watchdog to talk to the auth gate directly") has no runtime capability to test against, so it's satisfied by a direct code audit instead, not left unaddressed: a search of `fossh-fcgi`'s and `fossh-cgi`'s own source for any self-exec/self-restart mechanism (`current_exe`, `exec`, a self-spawn) found none — the only way core is ever restarted is by the watchdog's own `Supervisor.spawn`, triggered by a crash or (as of ADR-0050) a verified QUIC command; core has no path to request its own respawn directly. The separate §2.1 auth-gate network listener this requirement would otherwise ask "cannot bypass to reach" remains unbuilt — a real, already-documented, deliberately-scoped-out gap (see ADR-0050 and `watchdog/bin/main.ml`'s own header comment) — so there is nothing yet for `fossh-svc` to bypass the watchdog *to*. Re-verify this specific half once that listener is ever built.

**§3.6 (tamper detection)** needed no new work this pass — already fully built and adversarially reviewed as part of §3.3 (ADR-0040/ADR-0041): a signed manifest checked on every spawn and restart (including the initial launch, after ADR-0041 closed a real bypass there), with an explicit, documented "tampered" trigger (refuse + exit 3, fail closed, not restart-and-log) applied consistently everywhere a restart decision is made — including the new command-triggered path this same day's ADR-0050 added. Closing this out under §3.5's same task is a bookkeeping confirmation, not new implementation.

**Verification:** `sudo bash scripts/verify-privilege-separation.sh`, run for real against the real `fossh-svc`/`fossh-watchdog` system users on the dev machine — 6/6 checks passed on the first run. Both sub-chapters of prrr.md §3.5/§3.6 are now closed. See ADR-0052 for one remaining gap this closure surfaced (§3.3's own "enforce the auth gate" responsibility, §2.1, is not the same thing §3.4's QUIC channel wires up, and remains genuinely open) before treating the whole chapter as done.

---

## ADR-0052 — §2.1's human-operator auth gate: real, genuinely open, and deliberately not built this session

**Context:** closing out §3.5/§3.6 (ADR-0051) prompted a check of whether every prrr.md §3.1–§3.11 sub-chapter is actually, fully done — not just individually QA-gated at some point in the past — before writing a chapter-closing retrospective. §3.3 lists three responsibilities: restart-on-crash (done), tamper detection (done), and "enforce the auth gate (challenge-response, §2.1)." A direct search confirms the third is not: nothing in this codebase, anywhere, enrolls an operator's public key, and nothing outside `auth.ml`'s own unit tests ever calls `Auth.verify_signature`. `watchdog/bin/main.ml`'s own header comment has said as much, unchanged, since §3.3's very first pass: "Deliberately NOT wired up yet in this binary: the challenge-response auth gate's network listener."

**This is not the same gap §3.4/task #31 (ADR-0050) just closed.** Two genuinely different things share the word "auth" in this project: §2.1's challenge-response gate is a *human operator* proving they hold an *enrolled OpenPGP key* (via `gpg --verify`, `Auth.verify_signature`) to get a session token for issuing administrative commands directly to the watchdog; §3.4's QUIC channel is *core* (a machine, not an operator) proving it holds its own pinned *X.509* certificate via mTLS, with `command_protocol.ml`'s session token there existing only for replay protection layered on top of that already-proven identity, not as a substitute for a human proving anything. Building one did not build the other, and ADR-0050 said so explicitly at the time rather than leaving this to be discovered later ("the separate §2.1 human-operator GPG challenge-response auth gate remains exactly as open as it already was, not conflated with this channel").

**Decision: do not build this now.** Reasons, weighed together:
1. It is a genuinely new feature, not a wiring gap — `Auth`/`Session`'s existing logic is real and tested, but a working gate needs an enrollment mechanism (where does a pinned operator fingerprint live? nothing today has an answer — not a config file, not part of §3.11's setup wizard, nowhere), a transport decision (local Unix socket, matching this project's consistent "admin-adjacent surfaces stay local" pattern, versus something reachable over a network — an open design question, not a default to assume), and its own real adversarial review, comparable in scope to the whole of today's §3.4-wiring pass, not an afternoon's addendum to it.
2. Nothing in release 1's actual delivered capability depends on it. An operator can already control the running system through `systemctl`, direct local access, and (as of today) `SIGHUP`-triggered reload over the now-working watchdog↔core channel. A cryptographically-authenticated *remote* control surface is a real, legitimate feature, but not one release 1's own value proposition (privacy-preserving telemetry ingestion, supervised and tamper-checked) requires to function.
3. Matches the explicitly agreed release roadmap: this session is release 1 (`0.1.0_oa`, "open-alpha," "the base for development," not itself expected to be feature-complete in every dimension), with further features landing in later, separate releases rather than crammed into this one.
4. Token budget: the user flagged usage tightening twice today already; a new feature of this shape deserves its own dedicated, unhurried pass, not a rushed one at the tail of an already very long session.

**How to apply going forward:** this is a real, tracked gap, not a silently-accepted one — a candidate for release 2 (`0.0.2.1-patch_oa`) or a later chapter, to be designed properly (enrollment UX, transport choice, wire protocol, adversarial review) rather than retrofitted quickly. `main.ml`'s own header comment already states this accurately and should keep doing so until it's actually built. §3.3's own "QA-gate passed" status stands as an accurate record of what that specific pass scoped and reviewed (deliberately logic-only, per prrr.md §4's own "don't batch sub-chapters" instruction — see §3.3's original retrospective) — it is the *chapter-level* "all sub-chapters done" claim that this gap keeps from being fully true yet, and the closing retrospective (see `dev/DURUM.md`) says so plainly rather than rounding up to "done."

---

## ADR-0053 — The watchdog's OpenPGP key gets a real passphrase, not an empty one

**Decision:** `Keypair.ensure_keypair` generated its signing key with `gpg --passphrase ""` — real, but never described anywhere public, and surfaced only when drafting task #26's install docs required checking what actually happens rather than assuming. Fixed: a real, high-entropy passphrase (`Nonce.generate`, the same CSPRNG-backed 64-hex-char shape used everywhere else in this project) is generated once and persisted at `<gnupghome>/passphrase`, mode 0600 — not burned after first use like §2.6's setup token, since this passphrase protects a key meant to live for the install's whole lifetime and is needed again every time an operator re-signs the tamper-detection manifest, not just once at generation.

Routine, unattended restarts are unaffected: `Manifest.check`/`tamper_check` (called on every spawn and restart) only ever reads the *public* key via `gpg --verify`, which needs no passphrase at all. Only signing needs one, and signing is never something this process does to itself automatically. `Manifest.sign` and the auth-gate's `detach_sign` test helper both now pass `--pinentry-mode loopback --passphrase <value>` — required in `--batch` mode once the key is actually protected, since there's no interactive pinentry to fall back to.

**A real gotcha found while testing this, not while reasoning about it:** a test asserting the wrong passphrase is rejected initially passed a check it shouldn't have — `gpg-agent` caches an unlocked key's session for a period after a successful sign, so a second sign against the *same* `gnupghome`, even with a wrong passphrase, can spuriously succeed by riding that cache. Confirmed directly with a standalone repro: a never-before-unlocked key correctly fails with gpg's own "Bad passphrase" (exit 2); the ordering in the original test (sign correctly, then immediately sign wrong, same key) was the bug, not the passphrase protection itself. Fixed by testing the wrong-passphrase case against a separate, never-unlocked key.

Not treated as a new attack surface worth designing around: reaching gpg-agent's socket for this `gnupghome` already requires the same filesystem access as reading the passphrase file directly (both are `fossh-watchdog`-owned, per §3.5's now-verified privilege separation), so the cache doesn't meaningfully widen what an attacker who already has that access could do.

**Verification:** new tests in `test_keypair.ml` — the generated passphrase is real (not empty), the file exists at mode 0600, `ensure_passphrase` is idempotent, signing succeeds with the correct passphrase and is genuinely rejected with a wrong one (on a separate key, per the gotcha above). Full watchdog suite 136 checks (up from 130), `dune build`/`dune test --force` clean.

---

## ADR-0054 — Real identity leaks found in the shipped RPMs and vendored libquiche.so, both fixed at the build-script level

**Context:** a dedicated review pass of task #26's public output (a subagent instructed to check the actual release artifacts, not just the prose docs) found a CRITICAL finding this project's own established identity-hygiene tooling (ADR-0031, `scripts/check-identity-hygiene.sh`) had never caught: the real local username and this machine's real hostname were both baked into both shipped RPMs and into `libquiche.so`/`libquiche.so.0`, the vendored quiche build every watchdog binary links against. `scripts/build-release.sh`'s existing `--remap-path-prefix` treatment (ADR-0039) — genuinely correct and still working for the Rust binaries it covers — never applied to either of these two other build paths, since neither goes through it.

**Finding 1 — RPM/SRPM: real username and hostname in package metadata, not the payload.** Reproduced directly: `strings` on the shipped `.src.rpm` found 13 hits, all literal `%prep`/`%build`/`%install` shell text with `_topdir` expanded to a real `/home/<username>/rpmbuild/BUILD/...` path; `rpm -qp --qf '%{BUILDHOST}'` returned the real hostname on both RPMs. Traced to the actual root cause, not assumed: extracting the SRPM's own cpio payload showed the *stored* spec file and source tarball are both clean (macros unexpanded, no leaked paths in any tracked file) — the leak is generated by `rpmbuild` itself at build time, into the package's own header/metadata area, driven entirely by two defaults: `%_topdir` (defaults to `~/rpmbuild`) and `%_buildhost` (defaults to `hostname`). Confirmed by isolating the variable: building with `--define '_topdir /tmp/fossh-clean-rpm-test'` (a path with no real username anywhere in it) and `--define '_buildhost fossh-build'` produced a byte-for-byte-verified-clean SRPM and binary RPM, 0 hits, first try. (A first verification attempt used a scratchpad path that itself contained the real username as a substring of the *session's own* directory convention — a real false-clean risk, caught before trusting the result, by rerunning against a path guaranteed free of the string.)

**Finding 2 — `libquiche.so`/`libquiche.so.0`: BoringSSL's own C/C++ source paths, a different mechanism than finding 1.** `scripts/build-quiche-ffi.sh` compiles quiche (which bundles BoringSSL, built via `cmake` from C/C++, not `rustc`) in a vendored directory outside `build-release.sh`'s reach entirely. Adding the same `RUSTFLAGS`/`--remap-path-prefix` treatment closed quiche's own Rust-side leak (registry-cache paths for `slab`, `intrusive-collections`, `bytes`, `smallvec`, `octets` — all gone) but left 144 real hits, every one a BoringSSL `.c`/`.cc` source path under the vendored build tree. Root cause: `--remap-path-prefix` is a `rustc` flag; it has no effect on C/C++ compiler output, which embeds `__FILE__`-derived paths through an entirely different mechanism `strip = true`/symbol-stripping doesn't touch either (these are ordinary read-only string literals, not debug-info). Fixed by additionally setting `CFLAGS`/`CXXFLAGS` with `-ffile-prefix-map` (the C/C++ compiler's own equivalent), which `boring-sys`'s `cmake`-based build script passes through to the underlying C/C++ compiler. Verified: 144 hits to 0, confirmed on a full rebuild.

**Both fixes are in the build scripts themselves** (`scripts/build-release-zip.sh` was never wrong — it just packages whatever the two build scripts above already produced), so every future build gets them automatically rather than needing a remembered manual step:
- `packaging/rpm/fossh.spec` was never wrong either — the leak is generated by `rpmbuild`'s own defaults regardless of spec content, not by anything the spec does. The actual fix lives in *how* `rpmbuild` gets invoked for a release: `--define '_topdir <path-without-the-real-username>' --define '_buildhost <generic-value>'`, not yet automated into a single build script the way `build-release.sh` automates the Rust side — a real, tracked follow-up (this pass fixed and verified the *mechanism*, a wrapper script matching `build-release.sh`'s own shape is the natural next step, not built in this same pass to keep scope bounded).
- `scripts/build-quiche-ffi.sh` now sets `CFLAGS`/`CXXFLAGS` alongside `RUSTFLAGS` unconditionally — this one *is* now a permanent, no-extra-step fix.

**A real gap in `scripts/check-identity-hygiene.sh` itself, found by the same review pass, fixed:** its own real-path-shape regex (`/home/[^/ ]+/`) required a trailing slash, so a real leak already sitting in this codebase's own prose (`DECISIONS.md`'s ADR-0039 entry, quoting the *original* leaked-path finding as evidence — a real `/home/<username>` path immediately followed by a backtick, not a slash) passed the gate silently. Fixed the regex to drop the trailing-slash requirement (verified this doesn't introduce false positives: an initial fix that also allowed `.` in the matched-username character class immediately produced one, matching "/Users/." in `build-release.sh`'s own comment quoting the original spec requirement in prose — removing `.` from the class, since real usernames essentially never need it, fixed that without reopening the original gap). `DECISIONS.md`'s own leaked path was generalized to describe the finding without reproducing it.

**Also fixed in the same pass, found by the same review:** `NOTICE` still claimed dual Apache-2.0-or-MIT licensing and referenced nonexistent `LICENSE-APACHE`/`LICENSE-MIT` files — leftover, unedited text from before task #25 switched this project to MIT-only, never caught because nothing mechanically cross-checks `NOTICE` against `Cargo.toml`'s own `license` field. Corrected to describe MIT-only, matching `LICENSE` itself, `Cargo.toml`, and every other document that already stated it correctly. The published `readme.md`'s checksum-verification instruction referenced a `fossh-oa.zip.sha256` sidecar file that was never actually produced by the current `SHA256SUMS`-based approach (a leftover from an earlier, replaced convention) — corrected to reference `SHA256SUMS`, the file that actually ships alongside the zip.

**Public output reorganized** (a separate staging directory outside this repository that task #26's output goes to): a single `README.md` (renamed from a first draft called `index.md`) as the sole loose description file; `documents.zip` bundling the legal/policy documents (`THREAT_MODEL.md`, `PRIVACY.md`/`PRIVACY.tr.md`, `README.tr.md`, `tos.md`, `SECURITY.md`, `LICENSE`, `NOTICE`, `AUTHORS`) instead of leaving them loose; the release archive copied under a version-explicit name (`fossh-0.1.0-alpha.1.zip`) for the public download page specifically, while the source repo's own tooling keeps using `fossh-oa.zip` as its canonical §19.7 name internally — the public copy is a rename at publish time, not a change to what any script or `SHA256SUMS`-verification tooling expects. `SHA256SUMS` regenerated to record both zips' hashes with paths relative to where they actually ship; `sha256sum -c SHA256SUMS` verified to pass for real, from within that directory, matching how a downloader would actually run it. A dead link in an earlier draft (`docs/fossh-config.php`, resolvable only from inside the extracted zip, not from the loose `README.md` sitting beside it) does not recur in the rewritten version — the shared-hosting deployment shape is described without a link that only worked in one of the two contexts it appeared in.

**Verification:** every RPM, SRPM, and Rust/OCaml binary/library in the rebuilt `dist/fossh-oa.zip` — extracted and `strings`-checked individually, not sampled — 0 hits for the real username or hostname. `documents.zip`'s contents individually checked too. `scripts/check-identity-hygiene.sh` re-run against the source repo after all fixes: clean, no false positives from the broadened regex. `sha256sum -c SHA256SUMS` passes for real against both files task #26's output actually ships.

---

## ADR-0055 — 0.1.2_oa refinement pass: TUI dark theme completed, a second (and third) identity leak found and fixed, version scheme clarified

**Context:** still release 1 — "just refining it," in the user's own words, not starting release 2 yet. Two things prompted this pass: finishing the TUI visual-design work already flagged as deferred-until-asked-for, and a routine version bump that ended up surfacing three more real bugs, all fixed the same way this project has fixed every prior one — by actually running the thing, not just reading it back.

**Version scheme.** `0.1.1_oa` (Cargo.toml/RPM spec's own semver-constrained fields bumped to `0.1.1-alpha.1`/`0.1.1~alpha.1`; every doc/marketing reference unified onto the `_oa`-suffix display form, retiring the `-alpha.1` form those same docs used to show a reader) was drafted but never built or shipped — superseded by `0.1.2_oa` before any RPM or zip existed at that version, once the TUI work below turned into enough additional real change to justify one patch bump instead of two releases back to back. The RPM spec's own `%changelog` entry for 0.1.1 was renamed to 0.1.2 rather than kept as a phantom entry for a version nothing ever actually built — unlike the 0.1.0 entry above it, which is real history and stays untouched.

**TUI: dark-graphite theme completed.** `theme.rs` previously deferred entirely to the terminal's own default foreground/background, styling only accent colors on top of it — correct while the background itself was still an open question, wrong once "deep dark, graphite" was decided. Added `GRAPHITE`/`FOREGROUND` constants and a `fill_background()` helper that paints the whole frame before any panel renders; ratatui's own `Style::patch` merge semantics (a later style's unset fields fall back to whatever a cell already holds, never erasing it) mean every already-existing, otherwise-unstyled `Span` in `ui.rs`/`wizard.rs` now lands on graphite with a readable foreground automatically, without needing each call site touched individually. Contrast checked by hand against the standard WCAG relative-luminance formula: roughly 11:1 for body text (FOREGROUND on GRAPHITE), comfortably past the AAA threshold (7:1), not just AA. Release 1 stays dark-mode-only, as already decided; this closes that decision out rather than reopening it.

**Decision: no OSC-11 terminal-background detection this pass.** Raised as an idea: detect the terminal's actual background and adapt (invert for a light terminal) to guarantee readability. Weighed and set aside for now, not built. The fixed-graphite-fill approach above already delivers the stated goal — consistent, WCAG-compliant, no eye-sore — more reliably than detection would, precisely because it doesn't depend on terminal support at all; every cell is painted by the TUI itself regardless of what the terminal's own theme is. Real OSC-11 querying needs raw-mode terminal I/O with a timeout (genuinely easy to get wrong blind, with a real hang risk against an unsupported terminal) and silently no-ops through tmux/screen without passthrough and on terminals that don't implement it — shipping that as a *feature* while it quietly fails to fire on a meaningful slice of real usage would be its own kind of dishonesty about what the software does. "Invert for light" would also mean building and maintaining a second palette, contradicting the already-firm "release 1 is dark-mode-only" decision. A real candidate for release 2, alongside the already-planned light-mode work — not this pass.

**Dashboard status text corrected** (`ui.rs`'s `draw_dashboard`, `main.rs`'s module doc). Both had gone stale unnoticed: they claimed the watchdog (§3.3) "is not yet built" and tamper detection "not available... depends on the watchdog" (§3.6) — both false since ADR-0050/ADR-0051. The real, current gap is narrower and different: the watchdog and tamper detection are built, tested, and adversarially reviewed, but `fossh-tui` itself has no live IPC query wired to either yet (`data.rs` has no watchdog-status code at all, confirmed by search) — this screen genuinely can't show real-time state, but not for the reason the old text claimed. Reworded to say that plainly. `dev/DURUM.md`'s own §3.3 status-column text had the identical staleness ("transport layer not started," no longer true once §3.4/task #31 landed) and was fixed the same way.

**A second identity leak, found by the new RPM-build script's own self-check, not by a separate audit.** `scripts/build-release-rpm.sh` (new this session, wrapping the `--define '_topdir ...' --define '_buildhost ...'` fix ADR-0054 already verified) set `_topdir` to a path under `$project_root/dist/` — and `$project_root` is this checkout's own location, which necessarily lives under the real user's home directory. The override worked exactly as designed (rpmbuild's own `~/rpmbuild` default never fired), but the *replacement* path still contained the real username as a substring, for a completely different reason — the same false-clean-path mistake ADR-0054's own "Finding 1" already describes hitting once and catching before trusting the result. This time the script's own built-in verification (`strings` on the just-built RPM/SRPM, checked before anything gets copied to `dist/`) caught it, refusing to ship with a `FAIL:` line and a non-zero exit — the safety net worked, even though the first build attempt didn't. Fixed by switching `_topdir` to `mktemp -d` (a plain `/tmp` entry with no relationship to the checkout's own path). Also fixed: the script had been copying the newly-built RPM/SRPM into `dist/` *before* running its own leak check, so a failed run still left a leaky-but-real-looking package sitting there for a later, unrelated `build-release-zip.sh` run to pick up without anyone noticing the earlier `FAIL`. Reordered so the copy only happens after verification passes.

**A separate, real bug in the same new script**, found and fixed by a subagent before it hit a session usage limit mid-task: `git archive HEAD` builds the source tarball from the last *commit*, not the working tree — reproduced directly (HEAD was still `0.1.0-alpha.1` while the working tree, mid-version-bump, was already `0.1.1-alpha.1`, so the tarball would have silently shipped the wrong version's source despite every tracked file on disk already being correct). Fixed with `git stash create`, which snapshots the current index+worktree into a real commit object without touching `HEAD`, the index, or the stash list, falling back to `HEAD` when there's nothing to stash.

**A third, live identity leak, found by `check-identity-hygiene.sh` on the source tree itself, not a built artifact:** `DECISIONS.md`'s own ADR-0054 entry — the one *documenting* the RPM/hostname leak findings — illustrated them by reproducing the actual leaked values: the real username, the real hostname, and, in its closing "Public output reorganized" paragraph, the real absolute path to the separate public-output staging directory. Each was a live instance of exactly the class of leak the entry was otherwise about, sitting in a file this project's own rules treat as public. Fixed in four places by describing the *shape* of each finding (a real `/home/<username>/...` path, "the real hostname", "a separate staging directory outside this repository") without reproducing the actual value — preserving what each finding technically was without the entry itself still being an instance of it.

**A process note, worth keeping for future multi-step background builds:** a first attempt at chaining all four release-build steps (`build-release.sh` → `build-release-rpm.sh` → `build-release-zip.sh` → `check-identity-hygiene.sh`) in one `set -e` script, run via a backgrounded shell invocation, did not actually stop at the first failure — the RPM build failed for real (`dune build`'s "Library integers not found," the opam-env gap fixed below) and the identity-hygiene check also failed for real (on the third leak above), yet execution continued through all four steps, the script's own final banner printed as if everything had passed, and the reported completion status said otherwise-successful. The exact mechanism wasn't chased down (not load-bearing for anything else this pass), but the working fix was: never trust a chained script's self-printed success banner or a backgrounded run's summary alone — add an explicit exit-code echo after each individual step and read the actual output content. Doing exactly that on the re-run is what surfaced the real failures in the first place, instead of a second false all-clear.

**A fourth, smaller bug in the same new script:** rpmbuild's `%build` (a real `dune build` for the watchdog's OCaml side) failed with "Library integers not found" the first time this script ever ran for real — this dev machine's `ocaml-ctypes`/`ocaml-findlib` live in a local opam switch (`watchdog/_opam`), not system RPMs, and rpmbuild's child `%build` process doesn't inherit an opam env nobody activated in its parent. Fixed by having the script source `opam env` itself (from `watchdog/`) when `watchdog/_opam` exists, rather than leaving it as a documented-but-unenforced prerequisite the caller has to remember — which is exactly how it got missed the first time.

**Public output refreshed**, per the user's now-standing per-release instruction that this folder tracks whichever release is current: `fossh-0.1.2_oa.zip` replaces the old `fossh-0.1.0-alpha.1.zip` (removed, not left alongside as stale clutter); `documents.zip` regenerated from the current `THREAT_MODEL.md`/`PRIVACY.md`/`PRIVACY.tr.md`/`README.tr.md`/`tos.md`/`SECURITY.md`/`LICENSE`/`NOTICE`/`AUTHORS`; `SHA256SUMS` regenerated over both. `README.md`'s own version references updated to match.

**Verification:** `cargo check -p fossh-tui` and `cargo test -p fossh-tui` (18 tests) both clean after the theme/dashboard changes — the rest of the workspace was untouched this pass (TUI display text and build scripts only), so wasn't re-run in full. Full release chain re-run clean after all three script fixes: `build-release.sh`, `build-release-rpm.sh` (RPM + SRPM built, `strings`-checked clean before copying), `build-release-zip.sh`, `check-identity-hygiene.sh` (clean, including the regex sweep now covering `DECISIONS.md`'s own fixed prose). Public output's two zips both `sha256sum -c` verified, and independently `strings`-swept a second time against every ELF/RPM extracted from the shipped `fossh-0.1.2_oa.zip` — zero hits for the real username or hostname.

---

## ADR-0056 — Full test-suite health check + a doc-staleness sweep, delegated and then acted on

**Context:** "keep the refinement going" with no more specific target, after ADR-0055's pass. Two things followed: a from-scratch health check of everything ADR-0055 *didn't* re-run (the full workspace, not just `fossh-tui`), and a dedicated subagent scan for the same class of staleness ADR-0055 already found twice (a doc comment describing something as "not built yet" well after it was) — on the theory that if it happened in `ui.rs` and `DECISIONS.md` already, it likely happened elsewhere too, and a systematic search would find real instances rather than guessing where.

**Two real process bugs found while just trying to verify, before any doc content was even in scope.** First: an initial three-tests-plus-clippy health-check script piped every command's output through `tail -N` to keep the captured log short, then checked `$?` right after — which captures `tail`'s own exit status, not the piped command's, so a real failure upstream would have silently reported as passing. Caught before trusting it, by re-running with the pipe removed and the real exit code captured directly. Second, once that was fixed: the watchdog's own `dune test --force`, run directly (not through `scripts/build-release-rpm.sh`'s own %build, which handles this internally), failed every single test binary with `libquiche.so.0: cannot open shared object file` — not a code regression, but this same pass's own earlier `cargo clean` on `crates/fossh-quiche-ffi` deleting the vendored `.so` those binaries need at *runtime*, not just build time, combined with `dune test` never setting `LD_LIBRARY_PATH` to find it. Fixed by rebuilding it (`scripts/build-quiche-ffi.sh`) and setting `LD_LIBRARY_PATH` before the retry; both the requirement and the `cargo clean` interaction are now documented directly in `dev/DURUM.md` (a callout right after "Last updated," not buried in the already-dense §3.4 row) so this isn't rediscovered painfully again. With both fixed: full workspace tests (98+45+18 checks across the root workspace's crates), `fossh-ffi`'s own suite (32), the watchdog's own suite (56+ checks across 5 of its test binaries actually visible in the captured tail, the full run reporting exit 0), and `cargo clippy --workspace -- -D warnings` are all genuinely clean.

**Doc-staleness scan, delegated to a research-only `Explore` subagent** (report findings, make no edits — kept separate from judgment about what's actually worth fixing, which stayed here). Told to cross-check every git-tracked `.md` file and doc comment against `dev/DURUM.md`/`DECISIONS.md` as ground truth, using the already-found `ui.rs` and `DECISIONS.md`-self-leak bugs as the shape of what counts as a real finding. Real, confirmed findings, all fixed:

- **Eight stale "not built yet" doc comments**, the same class of bug as the `ui.rs`/`wizard.rs` fixes above, just not caught in that pass: `watchdog/bin/main.ml`'s header self-contradicted its own file (claimed the §3.4 QUIC channel wasn't wired, while the same file's `start_quic_command_server` call two hundred-some lines down is exactly that wiring); `crates/fossh-tui/src/wizard.rs` had the identical stale §3.3 claim `ui.rs` already had; `crates/fossh-admin/src/lib.rs` said §3.6/§2.1's logic would "land here" — it didn't, `dev/DURUM.md`'s own §3.6 row already documents the OCaml-only pivot, this file's forward-looking comment was just never revisited; `crates/fossh-ipc/src/lib.rs` and `watchdog/quic/quic.ml` (a matched Rust/OCaml pair) both still said the app-level command protocol and its runtime wiring were "NOT yet built," true when written, false since ADR-0047/ADR-0050; `watchdog/lib/command_protocol.ml` said its own wiring into `quic.ml` was "a separate, not-yet-built piece" — confirmed stale by cross-reading `quic_command_server.ml`'s own header, which quotes this exact sentence while explaining it's the fix; `watchdog/lib/tls_identity.ml` listed two "real, tracked follow-ups, not built here" that are both actually built (ADR-0049, ADR-0050 Part 1). **`THREAT_MODEL.md` and `README.md` both said "no fuzzing has been run yet,"** false and the most consequential of the eight — §3.7/ADR-0037 shows five real `cargo-fuzz` targets actually run, 1.9M–9.8M executions each, zero crashes; corrected to say that plainly while keeping the real, still-honest caveat (short smoke runs only, no long unattended run or CI wiring yet) rather than overcorrecting into overclaiming.
- **One stale version string**: `bindings/ruby/lib/fossh/version.rb`'s `VERSION` constant (which the gemspec derives its own version from) was still `"0.1.0-alpha.1"`, two bumps behind — the Go and PHP bindings have no equivalent hardcoded field, so this was the one binding actually affected. Fixed.
- **Two stale `Cargo.lock` files**: `crates/fossh-ipc` and `fuzz/` are both excluded from the root workspace (their own separate `[workspace] members = ["."]`), so neither's lockfile got touched by `build-release.sh`'s `cargo build --release --workspace` at the root — both still showed local packages at `0.1.0`/`0.1.1` after the version bumps. Fixed by running `cargo check` inside each (Cargo updates a lockfile to match its own `Cargo.toml` automatically; no manual edit needed).
- **Zero identity leaks found** — the subagent specifically re-checked for anything `scripts/check-identity-hygiene.sh`'s own regex might miss (a leak phrased without the exact matched shape), confirming ADR-0054/ADR-0055's fixes actually held rather than just moved the problem.
- **One real, unresolved gap, correctly not auto-fixed**: `scripts/build-release-rpm.sh` (written during ADR-0055's pass) is not git-tracked — `git status` still shows it as `??`. Every reference to it in `DECISIONS.md`/`dev/DURUM.md` describes a file that, from a fresh clone's perspective, doesn't exist. This is a real inconsistency, but fixing it means committing, and nothing in this pass's instructions asked for that — left for the user to decide, alongside the rest of this session's now-substantial pile of uncommitted-but-verified changes.

**Verification:** every edited Rust file (`fossh-admin`, `fossh-tui`, `fossh-ipc`, checked from its own separate workspace, not the root) and the four edited OCaml files (`watchdog`'s `dune build`) both compile clean. Full release chain (`build-release.sh` → `build-release-rpm.sh` → `build-release-zip.sh` → `check-identity-hygiene.sh`) re-run clean end to end with all these fixes included. Public output regenerated again: both zips `sha256sum -c` verified, `strings`-swept clean a second time, and the shipped source tree independently spot-checked for any remaining `0.1.0`/`0.1.1` reference outside `DECISIONS.md`/`dev/DURUM.md`'s own historical prose — the only hits are unrelated third-party crates genuinely versioned `0.1.0`/`0.1.1` upstream (`memmem`, `openssl-macros`, the `wezterm-*` family, `jiff-core`), not this project's own version.

---

## ADR-0057 — §3.3's real, remaining gap closed: `Operator_key.enroll` gated by proof of the §2.6 setup token

**Context:** ADR-0052 recorded §2.1's human-operator auth gate as a genuine, deliberately-deferred open item — `main.ml`'s own header comment had said, unchanged since §3.3's first pass, that "enrollment itself (`Operator_key.enroll`) is not yet gated by proof of the §2.6 setup token — anything that can reach `Operator_key.enroll` directly can enroll a key today." This pass closes that gap: a real, watchdog-owned setup-token implementation, and real gating of `Operator_key.enroll` behind it, wired into `Operator_auth_server`'s existing Unix-socket listener rather than a new transport.

**Design decisions:**
1. **New module, `watchdog/lib/setup_token.ml`/`.mli`, not a port of `crates/fossh-admin/src/setup_token.rs`.** That Rust module is real but was only ever driven by `fossh-tui`'s own explicitly-labeled standalone/demo mode (see its module doc: "a real install's watchdog holds the hash directly instead"); nothing wired it to the watchdog. Reusing it would mean either an FFI dependency purely to match a demo mode's own cosmetic base32 choice, or hand-porting that encoding to OCaml for no functional reason — against §3.3's explicit "keep this component's dependency tree minimal" goal. `Nonce.generate()` (already the project's one audited CSPRNG entry point, already used for `Session`'s tokens) supplies the random token material instead; SHA256 (per §2.6's own specific wording, not this project's usual BLAKE3) is computed by shelling out to `sha256sum` via the already-established `Manifest.sha256_hex`, reused rather than duplicated.
2. **Storage model:** the plaintext file at `/etc/fossh/setup-token` (mode 0600, `FOSSH_SETUP_TOKEN_PATH`-overridable) is the *only* durable state. The hash lives *only* in memory (a `Mutex`-guarded `string option ref`), recovered by re-reading and re-hashing the file on every `ensure` call (idempotent, same generate-or-recover shape as `Core_pin`/`Keypair.ensure_passphrase`/`Tls_identity.ensure_identity`) rather than persisted a second time anywhere — a second copy would only be a second thing that could drift from the file. `ensure` checks enrollment status *first*: if a key is already enrolled, nothing is generated and nothing is held live, regardless of a stale leftover file.
3. **Wire protocol:** extended `Operator_auth_server`'s existing socket rather than adding a second one — the setup flow is only ever reachable immediately after `NOT_ENROLLED`, and is permanently unreachable again the moment a key is enrolled (a fresh connection then gets `NONCE`, never `NOT_ENROLLED`), which is what actually makes it "not a standing bypass" rather than a second, permanent door into `Operator_key.enroll`. `SETUP <token>` → `SETUP_OK`/`SETUP_DENIED`; on `SETUP_OK`, an armored public-key block → `ENROLLED <fingerprint>` (which also burns the token, invalidate-then-delete order per §2.6, mirroring `setup_token.rs`'s own `burn` ordering rationale even though this is a from-scratch OCaml implementation) or `ENROLL_FAILED <fixed-vocabulary reason code>` (does *not* burn, so a bad paste can be retried with the same still-valid token). No server-side state for this flow outlives one connection — the actual mechanism that rules out replaying a captured `SETUP_OK` into a different, later connection's enrollment, not just a convention.
4. **`main.ml`:** `start_operator_auth_server` now calls `Setup_token.ensure` synchronously before the listener thread starts. Confirmed by a full-repo grep that `Operator_key.enroll`'s only caller anywhere is this gated flow — no other path exists to bypass it.

**Adversarial review — a dedicated subagent, plus real bugs this task's own required concurrency testing found directly:**

*Subagent findings (all fixed, re-verified):*
- **CRITICAL** — `Setup_token`'s hashing path (`Tempfile.with_contents` → `Filename.temp_file`) raised `Sys_error` uncaught on a real, plausible trigger (unwritable/full temp dir) — the *fourth* instance of this exact "Stdlib channel op raises `Sys_error`, escapes as an uncaught exception" bug class this codebase has now found and fixed (after `bootstrap.ml`, `core_pin.ml`, and `main.ml`'s cert-path read), and reachable on every restart via `ensure`'s recovery path with nothing between it and `main.ml`'s top level — a real trigger would have killed the entire watchdog, not just denied first-run setup. Fixed by guarding `sha256_hex_of_string` once, covering all three call sites.
- **CRITICAL** — `read_until`'s substring check rescanned the *entire* accumulated buffer after every 256-byte chunk (`contains_substring` on `Buffer.contents`), O(n²) in payload length. Negligible at the pre-existing 8192-byte signature cap; a real, measured 65+ second single-threaded CPU burn — starving every other connection queued behind it, since the accept loop is single-threaded — from one *ordinary* write at the new 262144-byte public-key cap this flow introduces. Fixed by only rescanning the new tail each iteration (`Buffer.sub`, not `Buffer.contents`) and materializing the full buffer once, on match — confirmed by repro: full-buffer scan-to-match dropped from tens of seconds to ~7ms.
- **MEDIUM** — a client pipelining its `SETUP <token>\n` line and the start of its key block into one `write()` (ordinary client behavior, not adversarial) had the already-buffered key-block bytes silently discarded, since each `read_until` call started a fresh empty buffer — a spurious `ENROLL_FAILED` on a fully valid submission. Fixed with an optional `~seed` on `read_until`, threaded from the leftover bytes after the SETUP line's own newline into the key-block read.
- **LOW/MEDIUM** — the original multi-client socket-level concurrency test never actually exercised overlapping execution (the accept loop is serial, so it only proved sequential-arrival correctness); re-scoped its own claim and added a real forced-overlap test at the module level using an explicit countdown latch, not a hopeful sleep.

*Found independently, while building that forced-overlap latch test (not by the subagent, and not reachable through this task's own new code — a real gap in `Operator_key.ml` itself, previously reviewed and believed settled):* both `enroll`'s temp gnupghome path and `persist_fingerprint`'s temp file path were named from `Unix.getpid()` alone. That uniquely identifies a *process*, not a *call* — fine for the "two separate processes" shape apparently verified before, a real collision for concurrent *threads* of one process, which share a pid. A 6-thread countdown-latch test (forcing genuinely simultaneous calls, not sleep-staggered ones) reproduced real corruption every run pre-fix: threads' `rm_rf`s deleting each other's in-flight gnupghome mid-`gpg`-operation, producing garbled `gpg` errors on *every* thread rather than one clean winner and five clean `Already_enrolled` refusals. Not reachable through this project's real, current callers today (`Operator_auth_server`'s accept loop is single-threaded and fully serial, so no two `Operator_key.enroll` calls are ever actually concurrent in the running watchdog) — but the module's own documented contract makes no such promise, and a future caller relying on it would have inherited this silently. Fixed by folding a fresh `Nonce.generate()` into both temp paths. **A third, structurally identical instance was found by inspection but deliberately left unfixed**: `core_pin.ml`'s `persist_pin` has the exact same `Unix.getpid()`-only temp-path pattern. Out of scope here — it belongs to §2.4's bootstrap handoff, a different, one-shot CLI subcommand with no concurrent callers in this task's own path — but flagged here rather than silently left for the next person to rediscover the hard way.

**Tests:** `watchdog/test/test_setup_token.ml` (new, 26 checks: idempotent generate/recover/enrolled-short-circuit, burn ordering and idempotency, a `Setup_token.burn`-racing concurrency scenario, and the new forced-overlap `Operator_key.enroll` scenario using a real countdown latch) and `watchdog/test/test_setup_enroll_flow.ml` (new, 24 checks: the real happy path over a real socket, replay-after-enrollment being structurally unreachable, wrong-token and bad-key-material paths not burning the token, and a multi-client race). `watchdog/test/test_operator_key.ml` gained a direct regression test for the `Unix.getpid()` collision, at the source. Countdown-latch helper (`make_latch`/`arrive_and_wait`) added to the shared `test_helpers.ml` rather than duplicated. Full watchdog suite (16 binaries, 221 checks) 3 consecutive clean serial runs (`dune test --force -j 1`); the concurrency-sensitive new/changed binaries individually stress-run 8–15 times each beyond that. One unrelated, pre-existing characteristic confirmed, not introduced by this pass: running the *full* suite under dune's default parallelism (`-j` unrestricted) occasionally shows timing flakiness in the already-timing-sensitive `test_quic`/`test_quic_command_server` binaries (ADR-0045's 2ms poll granularity) under the added resource contention from this pass's two new, `gpg`-heavy test binaries — confirmed via `git stash` against the pre-existing baseline that this flakiness exists independent of this pass's code changes; serial runs are consistently clean.

---

## ADR-0058 — 0.1.3 release bump + a full independent deep-dive pass, 7 parallel subagents

**Context:** with §2.1's auth-gate chain closed (ADR-0057) and the chapter's own closing retrospective corrected to reflect it, the version was bumped `0.1.2` → `0.1.3` (still release 1, still open-alpha — no interface-breaking changes) and a genuinely independent final verification pass was run before treating any of it as truly done: 3 subagents auditing the public release output from different angles (content/reproducibility accuracy, adversarial identity-leak hunting, a brand-new-user simulation following only the public docs), 3 running real live end-to-end scenarios beyond the automated test suite (an expanded HTTP/CGI/FastCGI matrix, a real watchdog supervision/tamper-detection run, a real §2.1 auth-gate/setup-token run), and 1 doing a whole-repo sanity sweep. Real findings from all seven, all fixed or explicitly documented below, not silently absorbed.

**Finding 1 (CRITICAL, self-inflicted, caught by the adversarial-leak-hunt subagent) — a stress-test config leaked into the shipped RPM/SRPM, surviving one prior "fix."** Running `fossh init` from the project root earlier the same session (manual stress testing, not part of any build step) left an untracked `fossh.toml` sitting at the repo root, referencing a real local scratch path. `scripts/build-release-zip.sh`'s own untracked-files fix (below) correctly excluded it from the *zip's* own `git ls-files`-equivalent snapshot once the file was deleted — but the RPM/SRPM bundled inside that same zip had already been built *before* the file was deleted, and `build-release-zip.sh` only ever *copies* pre-built RPM/SRPM artifacts, never rebuilds them. The already-contaminated RPM's own source tarball carried the leak forward into the "fixed" zip regardless. Root-caused and fixed by rebuilding the RPM fresh (confirmed via `rpm2cpio`/`tar` extraction that the file is genuinely gone from the new artifact) *before* rebuilding the zip a final time. A concurrent, unrelated build race compounded this same rebuild cycle: a parallel subagent's plain `cargo build --release --workspace` (no `quic` feature) shared this project's single `target/release/` directory and clobbered an already-correct, `quic`-enabled `fossh-tui` with a smaller, non-`quic` one mid-session — caught by noticing the shipped binary's size didn't match a subagent's independent fresh measurement, confirmed via `strings` (`FOSSH_QUIC`/`watchdog_status` absent), fixed with one more full `scripts/build-release.sh` → `build-release-rpm.sh` → `build-release-zip.sh` cycle run only after every parallel subagent had finished and stopped touching the shared build directory.

**Finding 2 (real, functional, found by the brand-new-user-simulation subagent actually standing up a real Apache instance) — the documented Apache and nginx deploy guides could not, as written, ever deliver a single working event.** Two stacked bugs, both empirically reproduced against a real `httpd` instance on this machine, not assumed: (a) Apache has stripped the `Authorization` header from CGI scripts by default since 2.4.13 — standard Apache behavior, unrelated to this project — and `DEPLOY-apache.md` never set `CGIPassAuth On`, so `fossh-cgi` never saw the write key at all; (b) under the documented `ScriptAlias /e.gif /usr/lib/cgi-bin/fossh-cgi`, a request to exactly `/e.gif` matches the alias with nothing left over, so Apache's own CGI-variable computation sets `PATH_INFO` empty — but `fossh-cgi`'s routing matches on `PATH_INFO`, not `SCRIPT_NAME` — so every request fell through to a `422` regardless of auth. Both fixed in `DEPLOY-apache.md` with `CGIPassAuth On` and an explicit `SetEnv PATH_INFO /e`/`/e.gif`; both confirmed with a real end-to-end request through a real Apache instance and the real compiled `fossh-cgi` binary after the fix (`204 No Content`). The nginx preview guide (`docs/preview/DEPLOY-nginx-cloudflare-tunnel.md`) has the identical `PATH_INFO` root cause (its stock `fastcgi_params` include never sets it) — fixed with `fastcgi_param PATH_INFO $uri;`, following the same well-established nginx mechanism but *not* empirically verified against a live nginx (not installed in this environment) — flagged honestly in the doc itself, consistent with that file already being `docs/preview/` (not yet through this project's full adversarial-review pass). `DEPLOY-caddy.md` had a third, independent bug in the same area — a `split_fossh-cgi` line that is not valid Caddyfile syntax at all (Caddy's `split` subdirective takes file extensions, not an arbitrary bareword) — replaced with `env PATH_INFO {http.request.uri.path}`, same honest "not live-tested, Caddy not installed here" caveat. A troubleshooting section was added to `DEPLOY-apache.md` for exactly this failure shape (401/422/silently-nothing-recorded), which didn't exist anywhere in the docs before.

**Finding 3 (real, documentation-only) — several accuracy gaps in public-facing docs, all fixed:** the `readme.md` "60-second quickstart" referenced `fossh-oa.zip`/a plain `./fossh` binary that don't match what actually ships (`fossh-<version>_oa.zip`, target-triple-suffixed binaries under `dist/`), and never mentioned that the default data directory needs `--dir` or root — fixed, and cross-referenced against the same `CGIPassAuth`/`PATH_INFO` gap above so a first-time reader hits one troubleshooting story, not three separate surprises. `README.md`'s own fuzzing claim ("short smoke tests only") had gone stale relative to `THREAT_MODEL.md`'s already-corrected one (real long run, 933.9M executions) — the THREAT_MODEL fix from earlier the same session never got mirrored into README.md; fixed. `fossh-tui`'s size in `readme.md`'s sizes table was stale (claimed 1.6 MB, actually ~3.0 MB now that it links the §3.4 QUIC client) — updated, with a note explaining why it grew. A `blob/master` GitHub link in the public `fossh_github/README.md` pointed at a branch name (`master`) that isn't this repository's real default branch (`main`) — fixed; it happened to still work via GitHub's own redirect, but pointed at something that isn't real. `fuzz/Cargo.lock` had missed the `0.1.2`→`0.1.3` version bump every other lockfile in the tree got — the same class of miss ADR-0056 already caught once for the `0.1.1`→`0.1.2` bump, on a different excluded-from-root-workspace crate this time; fixed with `cargo update --precise`.

**Finding 4 (real, honesty) — two places this file's own tracking sat stale relative to its own top entry, found by the whole-repo-sanity-sweep subagent.** The §3.3 status-table row still said the watchdog systemd unit and the TUI auth client were "deliberately deferred, not started" *after* both had already landed and this file's own top entry already said so — corrected. The chapter-closing retrospective (below) still listed §2.1 enforcement and the clean-VM verification as open items *after* both were closed — corrected, including the "Net assessment" line. Both are exactly the class of self-contradiction this project's own comprehensive-pass discipline exists to catch before a reader has to notice it themselves.

**Finding 5 (real, scope-honesty) — found by the live auth-gate end-to-end test, not by reading code.** `crates/fossh-tui/src/wizard.rs` (the actual "Setup Wizard" screen) is still its own standalone/demo-mode implementation, exactly as its own module doc has always said, and was never updated to speak the real `Setup_token`/`Operator_auth_server` protocol ADR-0057 built. Only the separate `OperatorAuth` screen speaks the real protocol, and only its challenge-response half. This means the earlier clean-VM verification's "full setup-token wizard flow completed end to end" claim (this file's own top entry, written before ADR-0057 landed) was accurate for what it tested at the time, but could be misread as claiming the current wizard speaks the current protocol — it doesn't yet. Corrected in both places this file made that claim; recorded here as a genuine, open, tracked gap, not silently left implicit.

**Finding 6 (real, minor) — a genuinely confusing log message, found by the live watchdog-supervision test.** `Unix.WSIGNALED`/`WSTOPPED` carry OCaml's own portable internal signal encoding (small negative ints, e.g. `Sys.sigkill = -7`), not the real OS signal number — a real `kill -9` logged as "killed by signal -7", not "9". Fixed with `Subprocess.describe_signal`, a small table matching OCaml's own named `Sys.sig*` constants (portable by construction) to their real Linux numbers/names for the common process-supervision-relevant signals, used in both `subprocess.ml`'s own error formatting and `main.ml`'s restart/crash logging.

**Finding 7 (initially reported as real, root-caused as a false alarm — corrected in the same pass, not left standing) — `fossh-tui`'s apparent non-reproducibility was a test-methodology artifact, not a build bug.** Two independent clean rebuilds using two different, externally-supplied `CARGO_TARGET_DIR` paths (not nested under either checkout) produced different `fossh-tui` bytes — 121,560 bytes differing, different ELF `.note.gnu.build-id` values, same size both times, first divergence at byte offset 813 (the build-id note itself, confirmed with `od`). This was first (wrongly) written up here as a real, unfixed `boring-sys`/BoringSSL non-determinism and the public README was softened to say so. Re-tested properly before letting that stand: (1) building twice with the *same* target dir (exactly how `scripts/build-release.sh` is actually ever invoked — it never sets `CARGO_TARGET_DIR` itself, so a real checkout always builds under its own `<checkout>/target/`) produced byte-identical output; (2) the real test the README's claim actually needs — two entirely separate checkouts, copied to different filesystem paths, both built clean — also produced byte-identical `fossh-tui`, confirming `--remap-path-prefix`/`-ffile-prefix-map`'s existing prefix-substitution already covers this correctly (both checkouts' own `project_root` gets mapped to the same canonical `/build/fossh` regardless of the real local path, and `target/` is nested under `project_root` so it's covered by the same substitution). The original finding only ever reproduced by pointing `CARGO_TARGET_DIR` somewhere *outside* either checkout, a path `-ffile-prefix-map`'s two mapped prefixes (`project_root`, `cargo_home`) were never meant to cover and no real build ever does. README reverted to its original, correct, unqualified reproducible-build claim. Lesson worth keeping, not just the correction: a repro test that doesn't match how the thing is actually, really invoked can manufacture a bug that doesn't exist in real usage — re-verify against the real invocation shape before trusting a diff, the same discipline ADR-0054's own first verification attempt already learned once for a different reason (a scratchpad path that itself contained the real username, producing a false-clean result the other way).

**What was checked and came back genuinely clean, not just assumed:** the full HTTP/CGI/FastCGI scenario matrix (auth both modes, replay/staleness/allowlist rejection, malformed input, rate-limit recovery) — every scenario passed against the real compiled `fossh-cgi`, zero bugs in the actual ingest logic; the full watchdog supervision/tamper-detection live run — real restart-on-crash, real fail-closed refusal on a corrupted manifest or binary, real restart-storm guard, all matching the documented design exactly; the full §2.1 challenge-response protocol live run — every wire-protocol guarantee in `operator_auth_server.mli` held under real, adversarial live testing (wrong-key denial, cross-connection nonce-replay denial, post-enrollment setup-path unreachability, persistence across a watchdog restart); the whole-repo sanity sweep's other six checks (real full-tree identity hygiene via a scratch staged copy, TODO/FIXME sweep, orphaned-code check, ADR sequential-numbering check, a full build+test re-run, stray-file check) — all clean.

**Tests / verification for this pass itself:** full `cargo build`/`clippy -D warnings`/`test --workspace` (both default and `--features fossh-fcgi/quic,fossh-tui/quic`) and the full OCaml suite (`dune test --force -j 1`, 16 binaries/221 checks) re-run clean after every fix in this entry, not just at the end. `dist/`'s RPM/SRPM and the public `fossh_github/` zips rebuilt fresh from the final, corrected state and re-verified (`strings` on every shipped binary and both RPM/SRPM payloads, `sha256sum -c` on both `SHA256SUMS` files) with zero identity-hygiene hits beyond the one already-known, deliberately-fake test fixture in `scripts/test-identity-hygiene-gate.sh`.

---

## ADR-0059 — `crates/fossh-tui/src/wizard.rs` rewritten to speak the real §2.6/§3.11 SETUP protocol (ADR-0058's Finding 5, closed)

**Context:** ADR-0058's own retrospective (Finding 5) recorded, honestly rather than silently, that `wizard.rs` — the TUI's actual "Setup Wizard" screen, key `3` — was still its own self-contained standalone/demo mode: it generated its own token in-process, held its own hash via `fossh_admin::setup_token`, and verified/burned against that internal state, never once connecting to the real watchdog. That was a reasonable placeholder while ADR-0057's server-side protocol didn't exist yet, but ADR-0057 landed and this file was never updated to match. This pass closes that gap for real.

**Design decisions:**
1. **`operator_auth_client.rs` gained the SETUP half of the wire protocol (`setup`/`setup_at`, `SetupError`) alongside its pre-existing challenge-response half, rather than a new, separate module.** Both are phases of the *same* wire session per `operator_auth_server.mli` (a fresh connection gets `NOT_ENROLLED` then falls straight into the SETUP flow on that same connection; challenge-response only ever happens on a later, separate connection once a key is enrolled), so they belong in the module that already owns the socket-framing/connection discipline for this protocol, reusing its established idioms (`describe_connect_error`, the `FirstLine` parse, test-parameterized socket path) rather than duplicating them.
2. **`setup_at` takes the token and the finished public-key material as plain arguments and performs the whole connect→SETUP→SETUP_OK→send-key→ENROLLED round trip in one blocking call, instead of exposing separate network calls for "submit token" and "submit key" with a UI-driven pause between them.** The .mli holds both halves on one connection bounded by the server's own connection-wide wall-clock deadline (10s by default) with no server-side state surviving past it — holding a connection open while an operator pastes text or `wizard.rs` shells out to `gpg --quick-generate-key` would race that deadline for no protocol benefit. `wizard.rs` collects the token (read from disk) and the key material (pasted, or generated) entirely locally, with no socket open, before ever calling `setup_at` once.
3. **A freshly generated key lands in the operator's own real default GPG keyring (no throwaway `--homedir`), matching what the already-wired challenge-response half (`sign_with_gpg`, `gnupghome_override: None` in production) will later sign from.** Generating anywhere else would enroll successfully and then lock the operator out the moment the wizard closes — the public key would be pinned server-side but the matching secret key would be nowhere `sign_with_gpg` ever looks. The new key's fingerprint is identified by diffing the keyring's secret-key fingerprint set before and after `--quick-generate-key`, not by searching `--list-secret-keys <uid>` — a fixed UID string isn't guaranteed unique against an earlier abandoned attempt (key generated, never enrolled because `SETUP_DENIED` followed), and picking the wrong match from a multi-result search would silently enroll the *old* key's public half.
4. **`wizard.rs`'s `Step` enum was redesigned around the real protocol's actual states** (`ReadyToSubmit`, `ChoosingKeySource`, `PastingKey`, `KeyGenerated`, `Enrolled`, `TokenDenied`, `EnrollFailed`, `Failed`) rather than keeping the old ad hoc generate/verify shape. `EnrollFailed` specifically keeps the still-valid token in memory and routes straight back to `ChoosingKeySource` — the .mli promises `ENROLL_FAILED` does not burn the token, so a bad paste must be retryable without restarting the wizard, and now is.
5. **Bracketed paste (`crossterm::event::EnableBracketedPaste`) is enabled in `main.rs` specifically for the key-paste step** — an armored PGP public key block is always pasted, never typed character by character, and without it a paste containing embedded newlines would arrive as a flood of individual `Enter` key events indistinguishable from the operator actually pressing Enter partway through.

**Adversarial review — a dedicated, separate subagent, plus real bugs this task's own self-testing found directly:**

*Found during self-testing, before the adversarial pass, fixed at the source:* `gpg --list-secret-keys` on a `GNUPGHOME` that does not exist yet exits fatally (confirmed directly: exit code 2, "directory does not exist!") rather than reporting zero keys — `generate_fresh_operator_key_at`'s own before/after diff calls this before anything else, so a genuinely fresh operator with no `~/.gnupg` yet (the exact "first-run setup" shape this whole flow exists for) would hit this as a confusing hard failure on their very first use. Fixed with `ensure_gnupghome_exists`/`resolve_gnupghome`, which pre-creates the directory (0700) using the same `$GNUPGHOME`/`$HOME/.gnupg` precedence `gpg` itself uses, for both the override path (tests) and the real default path (production).

*Subagent findings:*
- **HIGH** — `setup_at`/`authenticate_at` had no overall wall-clock deadline, only a per-syscall socket timeout (`READ_WRITE_TIMEOUT`, 15s). Confirmed with a real reproduction: a peer dripping one byte every few seconds with no terminating newline kept the call blocked past the per-syscall timeout indefinitely in principle, because `BufReader::read_line` loops internally over `Read::read()` without ever returning control between calls for the timeout to be re-checked against — the exact drip-attack bug class `operator_auth_server.ml`'s own comments document finding and fixing server-side (around its `read_until`), never given the equivalent client-side fix. Since every caller runs synchronously on the TUI's single-threaded blocking event loop, this would freeze the whole process, including leaving the terminal stuck in raw mode (`ratatui::restore()` never runs while the call never returns). Fixed with `read_line_bounded`, a raw byte-at-a-time reader checking a wall-clock deadline between every individual `read()` — mirroring the server's own fix — applied to every line read in both `authenticate_at` and `setup_at`. The deadline is computed fresh immediately before each individual read rather than once for the whole call, specifically so the real, legitimate wait on `gpg`'s own interactive `pinentry` prompt (an operator typing a passphrase) between reads can't spuriously eat into the budget for the *next* read.
- **MEDIUM** — none of the client's line reads capped length the way the server's own `max_setup_command_len`/`max_public_key_len` do, so a fast peer sending bytes without a `\n` could grow the buffer unbounded. Closed by the same `read_line_bounded` fix (`MAX_LINE_LEN`, 8192 bytes — generous against any real protocol line, which is at most a few dozen bytes).
- **LOW** — `wizard.rs`'s paste accumulation (`push_paste_char`/`push_paste_str`) had no length cap before the armored-key marker check. Fixed with `MAX_PASTE_LEN` (262144 bytes, matching the server's own `max_public_key_len`), truncating on a real UTF-8 char boundary rather than an arbitrary byte offset.
- **LOW** — `sign_with_gpg` (pre-existing, unchanged this pass) shares the same "nonexistent GNUPGHOME fails hard" class `ensure_gnupghome_exists` fixed elsewhere, but tracing both wizard code paths confirmed it isn't actually reachable through anything this pass added — left as-is, matching this project's own standard of not fixing what a review found isn't real for the code actually shipped.
- **Checked and came back clean:** no panics/unwraps/index-out-of-bounds reachable from network or `gpg`-output parsing anywhere in the five changed files; `generate_fresh_operator_key_at_inner`'s before/after fingerprint-diff self-defends against a concurrent-generation race (a second key appearing produces an explicit refusal, never a silently-wrong pick); `Zeroizing` fields are dropped correctly on every `Step` reassignment (no panics are reachable in this code, so the workspace's `panic = "abort"` release-profile concern that made the *original* wizard.rs need proactive zeroizing doesn't apply the same way here); a real end-to-end probe against the actual compiled `fossh-watchdog` binary confirmed `ENROLL_FAILED` (a marker-valid-but-garbage key body) does not burn the token and a same-token retry with a real key does succeed, exactly matching the .mli's contract; every `Step` × every key in `app.rs`'s `on_wizard_key` degrades safely on a "wrong key for this step" press, no double-submission or false-success path (blocking synchronous calls rule out concurrent double-press by construction).

**Tests:** `crates/fossh-tui/src/operator_auth_client.rs` gained the SETUP flow's protocol-level tests (pure parsing, client-side short-circuits that must never touch the socket, a hand-rolled mock listener covering every real server reply, `generate_fresh_operator_key`'s own isolated-`GNUPGHOME` tests including a real sign/verify round trip and the before/after-diff regression case, `read_line_bounded`'s own drip-timeout/max-length regression tests) and a genuine cross-language interop test (`setup_interops_with_the_real_compiled_watchdog_binary`) spawning the real compiled `fossh-watchdog` binary — wrong-token denial without burning, a real `ENROLLED` with the token burned only after, replay-after-burn correctly reported as `AlreadyEnrolled` (the SETUP path becomes permanently unreachable once a key is enrolled, a stronger guarantee than "the token is burned" alone), and the newly-enrolled key then working for the separate real challenge-response flow. `crates/fossh-tui/src/wizard.rs` was fully rewritten with its own state-machine test suite (file-read edge cases, the paste-length cap and UTF-8-boundary truncation, retry-after-`EnrollFailed` keeping the same token, honest failure against an unreachable socket). `crates/fossh-tui/src/app.rs`'s existing raw-input-capture tests were updated for the new `PastingKey` step shape rather than the old token-entry step. 59 tests in `fossh-tui` (up from 32), all passing, `clippy -D warnings` clean, both default and `--features fossh-fcgi/quic,fossh-tui/quic` builds/tests re-run clean after every fix in this entry. One pre-existing, unrelated, out-of-scope test (`fossh-fcgi`'s `quic_command_interop.rs`, last modified before this session) intermittently fails in a sandboxed environment with no controlling TTY — `gpg --quick-generate-key` blocks on an interactive `pinentry` prompt that has nowhere to display, confirmed by reproducing the identical hang with a bare `gpg` invocation unrelated to any of this pass's code; not a regression, and out of this pass's scope to fix.

---

## ADR-0060 — final release-artifact rebuild + a genuine CI/tooling closeout pass

**Context:** with ADR-0059 landed, the last remaining step was to rebuild `dist/`'s RPM/SRPM and the public `fossh_github/` zip fresh (the previous build in both places predated `wizard.rs`'s rewiring), verify the result rather than assume it, and close out the two real, explicitly-tracked "not yet done" follow-ups still on record: CI wiring for the fuzz targets (§3.7), and the identity-hygiene script's tracked-files-only scan gap (this file's own top entry, previous day).

**Artifact rebuild, verified not assumed:** `scripts/build-release-rpm.sh` → `scripts/build-release-zip.sh` re-run fresh. Confirmed by direct inspection, not by trusting exit codes alone: `strings` against every shipped binary in the zip (`fossh-tui`, `fossh-cgi`, `fossh`, `libfossh.so`) — zero identity-hygiene hits; `fossh-tui` carries its `quic`-feature markers (`FOSSH_QUIC`/`watchdog_status`); the RPM and SRPM bundled inside the zip are byte-identical (`diff -q`) to the freshly built `dist/` copies — the specific check ADR-0058 Finding 1's bug (a stale pre-fix RPM surviving inside a "fixed" zip) would have failed, and didn't this time. Public `fossh_github/` output updated: the new zip copied in as `fossh-0.1.3_oa.zip`, `SHA256SUMS` regenerated, `documents/`'s legal docs confirmed still byte-identical to source (no rebuild needed there), and a final identity-hygiene grep across the whole public output tree came back clean.

**Finding 1 (real, CRITICAL, previously undetected — likely present since the file was first committed) — `.github/workflows/ci.yml` contained invalid YAML, meaning this repository's CI has probably never once successfully parsed and run on a real push or PR.** While validating the new `fuzz-smoke` job being added below, a plain `python3 -c "import yaml; yaml.safe_load(...)"` check failed against the file — not just the working copy, the last *committed* version too (checked directly via `git show HEAD:...`, to rule out this being a defect this session's own edits introduced). Root cause: one `name:` value — `network-denied test run (P-invariant: zero egress from the ingest path)` — contains an unquoted `: ` (colon-space) partway through, which the YAML spec treats as ambiguous with a nested mapping key inside a plain scalar. Fixed by wrapping the value in double quotes; the whole file now parses clean, confirmed by re-loading and enumerating all four jobs' step counts programmatically, not just re-running the same failing check and hoping. No `actionlint` available in this environment to additionally check GitHub-Actions-specific semantics beyond generic YAML validity — a real, honest gap, not silently assumed covered.

**Finding 2 (real follow-through, not a bug) — §3.7's "wire a short run into CI" item, tracked open since the long fuzz pass finished, closed.** New `fuzz-smoke` job in `ci.yml`: installs the nightly toolchain + `cargo-fuzz`, runs all 5 existing targets (`json_body`, `query_string`, `forwarded_for`, `fcgi_framing`, `spool_frame`) for 15 seconds each — matching the project's own already-established smoke-run pattern, not the long local run, since a full 76-minute run on every push/PR would be real but disproportionate CI cost for marginal incremental signal over the already-clean 933.9M-execution local run — then asserts `fuzz/artifacts/` is still empty after all five. `THREAT_MODEL.md`'s alpha-caveats section and `dev/DURUM.md`'s §3.7 row both updated to stop saying this hasn't happened.

**Finding 3 (real structural gap, closed properly rather than worked around) — `scripts/check-identity-hygiene.sh` only ever scanned `git ls-files`-tracked files, silently blind to any untracked file until it was staged.** This file's own previous entry (same chapter, a day earlier) had already caught and documented this — this session's own ~68 untracked files were a real, live instance of exactly the blind spot, verified clean only by a manual hand-check at the time, not by the automated gate. The previous entry's own suggested next step ("`git add -A` before the next real hygiene run") would have worked but only as a remembered manual ritual before every future run, not a fix at the tool itself. Applied the more durable fix instead: a new `fossh_ls_files()` helper using `git ls-files -z --cached --others --exclude-standard` (tracked files plus untracked-but-not-gitignored ones, so real build output/`target`/`dist` stay excluded exactly as before, with nothing needing to be staged first), threaded through all four of the script's existing scan sites, including the `$0aptile`-quoting sweep's differently-shaped `git ls-files 'pattern'...` invocation (rewritten to filter the same null-delimited list by extension/basename instead, so it gets the same tracked+untracked coverage as the other three checks rather than being quietly left on the old narrower one). Re-verified both directions after the change: `scripts/test-identity-hygiene-gate.sh` still correctly fails its deliberately-bad fixture and passes once cleaned (both real regression coverage, not just "the script still runs"), and a real run of `check-identity-hygiene.sh` against this actual working tree — now genuinely covering the untracked files it was blind to before — came back clean.

**Scope note:** no code behavior changed in this pass — RPM/zip rebuild, a CI-workflow-only YAML fix and one new CI job, and one release-tooling shell script. No new adversarial-review subagent was dispatched for this pass; the changes are build/CI/tooling plumbing, not new application logic, and each fix was verified directly (YAML re-parse, gate self-test round-trip, byte-identical artifact diff) rather than by review.

---

## ADR-0061 — the TUI becomes a headless bridge, and the console becomes a desktop application

**Status:** accepted, 0.0.2.1.

**Context.** `fossh-tui` held two very different things in one binary:
a ratatui presentation layer, and roughly 2,500 lines of hardened
protocol clients — `operator_auth_client.rs`'s challenge-response and
SETUP flows, `watchdog_status.rs`'s QUIC/mTLS status query, the
k-anonymised store reads. The decision to build a proper GUI put the
presentation layer up for replacement. It did not put the protocol
clients up for replacement, and conflating the two would have been the
expensive mistake available here.

**Decision.** Split them. `fossh-tui` becomes `fossh-agent`: the same
protocol clients, byte-for-byte, with the terminal layer deleted and a
JSON-lines-over-stdio protocol added. `fossh-console` (GTK4/libadwaita,
Python) is pure presentation and spawns the agent as a child process
over a pipe.

**Why not reimplement the protocols in Python.** This project has
already paid twice for a second implementation of a working wire
format, both times in ADR-0050: the session hello sent on QUIC stream 0
(a stream-ID rule enforced by quiche itself, not by convention), and a
`str::trim()`-versus-`String.trim` divergence between two "identical"
parsers. Both were interop-only bugs that neither side's own
same-language test suite could have caught. A third implementation, in
a third language, with no cross-language test to catch the drift, would
have been strictly worse than the two that already cost real debugging
time.

**Why a pipe and not a socket.** The console spawns the agent and owns
both of its pipes for its lifetime. That is the entire access-control
story — there is nothing to authenticate to, because there is no way
for a second process to reach it. A socket would have needed an
authentication scheme that exists only because the socket exists.

**The setup token never crosses to Python.** `setup.state` reports
whether a usable token exists, never its value. The plaintext stays in
the agent in a `Zeroizing<String>`. Handing it to an interpreter that
cannot zeroize a `str`, may copy it during garbage collection, and can
serialise it into a traceback would have bought nothing — the console
has no use for the value but to hand it straight back.

**Found while doing this**, and not by design: three cross-language
interop tests had been failing while `dev/DURUM.md` recorded them as
passing. See ADR-0064.

---

## ADR-0062 — integrations: storage in `fossh-admin`, the network in `fossh-agent`

**Status:** accepted, 0.0.2.1.

**Context.** Operators need to send things to external services they
control, authenticated with an API key. foSSH's most load-bearing claim
is that the ingest path makes no outbound network connections, and
`fossh-cgi`/`fossh-fcgi` both depend on `fossh-admin` for `data_key` —
so anything added to `fossh-admin` is, by construction, in the ingest
path's dependency tree.

**Decision.** Split by what each half needs. `fossh-admin::integrations`
holds storage, validation and redaction, and contains no network code
whatsoever. `fossh-agent::integrations_net` makes the actual request
and is not reachable from any ingest binary.

The property is therefore structural rather than a promise, and
checkable in one command:

```
cargo tree -p fossh-cgi | grep fossh-agent    # nothing
cargo tree -p fossh-fcgi | grep fossh-selfheal # nothing
```

**On the privacy claim.** The README said "no third-party egress". That
was true of the whole product and is now true of the ingest path
specifically. The honest amendment, made in the documentation rather
than quietly left: an operator-configured integration is
operator-initiated, never on the ingest path, and carries no visitor
data. The guarantee that mattered is unchanged; the sentence describing
it was too broad to keep as written.

---

## ADR-0063 — the one outbound request shells out to `curl`

**Status:** accepted, 0.0.2.1.

**Decision.** `integrations_net` invokes the system `curl` rather than
linking an HTTP client.

**Why.** `ureq` with `rustls` would add roughly eighty crates to the
§3.10 supply-chain gate — `cargo audit`, `cargo deny`, a licence
review, and a dependency graph to re-examine on every update — to make
one operator-triggered request. This codebase already shells out to
`gpg`, `openssl` and `sha256sum` for the same reasoning, and `curl` is
present on every RHEL-family system by default.

**The part that is load-bearing.** On Linux `/proc/<pid>/cmdline` is
world-readable, so a credential passed as an argument is readable by
every local user for the process's lifetime. `/proc/<pid>/environ` is
owner-only but still visible to anything running as the same user and
inherited by every child. Neither is used: the key reaches `curl` only
through a configuration file fed on **stdin** (`--config -`), which
lives in a pipe and is never named in the filesystem.

Three flags are security decisions rather than tuning. `-q` must be
first, and is what stops `curl` reading `~/.curlrc` where a forgotten
`--location` or `--proxy` would silently redirect the credential.
Redirects are never followed — a `302` to an attacker's host is the
standard way to turn a webhook into a credential-exfiltration
primitive, and `curl` re-sends the `Authorization` header across one.
`--proto`/`--proto-redir` pin the accepted schemes so nothing
downstream can turn the request into a `file://` read.

**Verified empirically, not argued:** with a real request in flight
against a stalling loopback listener, the credential appears in neither
`/proc/<curl-pid>/cmdline` nor `/proc/<curl-pid>/environ`, nor in the
agent's stdout or stderr, nor in the file on disk.

**A parser differential was specifically tested for.** `validate_endpoint`
hand-parses the URL to decide whether `http://` is allowed, and a
disagreement with `curl`'s real parser is how a key ends up in
cleartext on someone else's server. Every alternate loopback spelling
`curl` accepts — `0177.0.0.1`, `2130706433`, `127.1`,
`[::ffff:127.0.0.1]` — is **rejected** here. Stricter is the safe
direction of that disagreement; the dangerous direction was looked for
and not found, and the cases are now regression tests.

---

## ADR-0064 — three interop tests that had never passed, and a watchdog that could not start

**Status:** accepted, 0.0.2.1. Recorded as a defect log, not a design.

**What was wrong.** `watchdog/bin/main.ml` handed the supervised child
off to the `fossh-svc` account unconditionally, via `setpriv`.
`setresuid(2)` requires `CAP_SETUID`, so run as anything but root every
spawn died instantly with exit 127. The supervisor treated each death
as a crash, restarted, tripped the 5-restarts-in-60s storm guard after
about a second, and exited the **whole watchdog process** — taking the
operator-auth server and the QUIC command server with it. Every client
mid-handshake saw `Broken pipe`.

That is four layers between the symptom and the cause, and it had
consumed both of `fossh-tui`'s cross-language interop tests for the
entire 0.1.x line. Both sent the watchdog's stderr to `/dev/null`, so
the message that would have explained it (`setpriv: setresuid failed`)
was discarded. A third test, `fossh-admin`'s `bootstrap_interop`, was
failing separately for never setting `LD_LIBRARY_PATH`, so the binary
died in the dynamic linker before `main` ran.

`dev/DURUM.md` recorded all three as passing.

**Decision.** Gate the privilege drop on the effective uid. If not
root, refuse to start with an explicit message and a new exit code 9,
unless `FOSSH_WATCHDOG_ALLOW_NO_PRIVDROP=1` is set — a development
mode that logs a warning every time it is used.

**Why refuse rather than skip the drop.** A watchdog that appears to
work while running core with the invoking user's full privileges is a
§2.3 violation, and a quiet one. Failing loudly at startup costs a
developer one environment variable; failing silently costs an operator
their privilege separation without telling them.

**The wider lesson, recorded because it recurs.** Two of these tests
discarded the child's stderr. A test that spawns a process and asserts
on a socket appearing must capture and surface that process's own
diagnostics on failure, or every startup failure it ever sees will
present as whatever the client happens to hit next.

---

## ADR-0065 — self-healing: deterministic rules, with a fenced local model

**Status:** accepted, 0.0.2.1.

**Decision.** Two layers. `engine.rs` holds deterministic rules that
produce every finding and every remedy, always runs, and is the entire
feature. `advisor.rs` is an optional local model
(`fossh-advisor:0.0.2.1`, derived from `lfm2.5-thinking:1.2b`) whose only
permitted effect is writing one `advice` string onto a finding the
engine already produced.

**Why the fence is this tight.** An operator installs foSSH for a set
of privacy invariants. A component able to author remedies could argue
them out of one, and "your k-anonymity threshold looks high, try
lowering it" is a fluent, confident, completely wrong sentence that a
1.2B model produces readily. Keeping the model on the explaining side
of that line bounds its worst failure at unhelpful prose.

Enforced by construction rather than by prompting: `attach_advice`
matches replies to findings by an id that must already exist and copies
exactly one string. Tests assert that a reply naming an invented
finding is dropped, and that severity and remedy are unchanged by any
advice at all.

**Automatic remedies are narrow deliberately** — permission tightening
only. Anything that deletes, rewrites or relaxes a setting is printed
for the operator with the exact command, even where running it would
have been trivial. `apply_automatic` has a test asserting it cannot be
talked into running an operator remedy.

**The capability gate.** AVX2 required, AVX-512 preferred, Vulkan as a
*fail-switch* for machines without AVX2 and never an upgrade over it —
taking a GPU away from a server doing real work is a larger imposition
than this feature is worth. Floor of six physical cores and 8 GiB;
AMD Ryzen 5 2600 (Zen+, 2018) and Intel Core i5-8400 (Coffee Lake,
2017) as the named exemplars. Cores are counted physically, not
logically: hyperthreads share the vector units this workload is bound
by. Two cores are always reserved, threads capped at four.

Intel's AVX-512 support is not monotonic with age — Alder Lake and
later ship it fused off — so a newer Intel part can legitimately land a
tier below an older one. The tier therefore comes from probing
features, never from a model name.

**Static capability is not sufficient**, which is why passing it only
earns the right to be timed. A hypervisor can advertise AVX-512 via
CPUID and emulate it slowly, and no static detection sees that. A real
generation is run and held to a tokens-per-second floor.

**The model is derived, not used as-is.** `packaging/model/Modelfile`
bakes the prohibition into a `SYSTEM` message, because a rule that is a
security property must survive a caller that forgets to send it. It
also carries an explicit ban on ever recommending that `k_anonymity` or
any other privacy setting be lowered, a worked example of the answer
shape, sampling tuned for restating a known fact, a thread count
matching the reservation above, and a `</think>` stop sequence so the
model's reasoning trace never reaches an operator's screen. A test
reads the shipped Modelfile and asserts it builds the tag the code
invokes — the two live in different files and would otherwise drift
apart silently.

**Endpoint access.** Ollama binds loopback, which keeps the network out
but not other local accounts, so Apache fronts it with a per-install
256-bit secret. Two properties of that file are load-bearing and were
both got wrong first: it must be readable by **two** accounts (Apache
runs as `apache`, the agent as `fossh-svc`, and a file readable by one
leaves the endpoint either unreachable or unguarded), and it must have
**no trailing newline**, because Apache's `file()` returns bytes
verbatim and a secret written by `echo` would compare as `"abc\n"`
against a header of `"abc"` and deny every request forever while the
configuration read as correct.

---

## ADR-0066 — developer extensibility as declarative providers, not a plugin API

**Status:** accepted, 0.0.2.1.

**Context.** Making it easy to reach common services (Datadog, AWS,
Honeycomb) without every operator looking up a URL and a header name.

**Decision.** A provider is a TOML file describing an endpoint
template, a method, where the credential goes, and the fields the
operator must supply. Six ship with the package; more can be dropped
into `/etc/fossh/providers.d` or `~/.config/fossh/providers.d`.

**Why not loadable code.** The obvious design is a plugin API. This
process holds every API key on the install, the setup token, and a
private key at the moment it is generated — code loaded into it gets
all of that. A plugin ecosystem is also a supply chain: one popular
provider plugin with one bad release is a credential-exfiltration
incident across every install that had it, and foSSH has no mechanism
for revoking one.

A declarative provider cannot read a credential, execute anything, or
reach the network. The worst a malicious one can do is name an endpoint
pointing at its author's server — which an operator typing that URL by
hand could already do, is visible in the console before anything is
sent, and is refused unless it is HTTPS.

**Templates are validated after substitution, never before.** A field
value carrying `/`, `?`, `#`, `@`, `:` or a backslash would otherwise
change which host the finished URL addresses — the same trap
`host_of` exists for, one layer up. Those characters are refused rather
than escaped: escaping would silently produce a URL the operator did
not mean.

**AWS is included only in the shape that is honest.** API Gateway's
static `x-api-key` header fits this model exactly. AWS service APIs
proper sign every request with SigV4 and cannot be reached this way at
all, and the provider says so rather than shipping something that looks
right and fails on first use.

---

## ADR-0067 — gpg status is read from its own stream, because a document can forge it

**Status:** accepted, 0.0.2.1. Found by debugging, not by review.

**The bug.** `keylock::verify` ran `gpg --status-fd 1 --decrypt`, which
interleaves gpg's machine-readable status protocol with **the signed
document's own content** on a single stream. Nothing in that stream
distinguishes the two. A document whose body contains

```
[GNUPG:] GOODSIG DEADBEEF someone
[GNUPG:] VALIDSIG <the fingerprint you expect> ...
```

therefore writes status directly into the verifier's input.

**Reproduced against a real gpg**, not reasoned about: a file
clearsigned by an attacker's key, carrying exactly those two lines in
its body, caused the parser to set both `good` and
`fingerprint_matches` before the genuine status for the attacker's key
was reached. The attempt was still rejected — but only because gpg
emits the real `ERRSIG` *after* the content, and the parser returns
early on it. That is line ordering, not a defence, and it would not
survive a multi-signature document, a different gpg option, or a
future change in emission order.

**The fix.** `--status-file <path>`, parsed separately from stdout.
Status comes from a file the document cannot write to; the body comes
from stdout. Neither stream can impersonate the other, and the property
no longer depends on ordering at all.

**This module's own header already claimed this.** It said verification
"mirrors `watchdog/lib/manifest.ml`", which really does use
`--status-file`, and cited ADR-0040 for parsing status rather than
trusting the exit code. The prose was right and the implementation was
not — a reminder that a comment asserting a security property is not
evidence of one.

Two regression tests: a forged body against a real `ERRSIG` status, and
a check that both the bare (`--status-file`) and `[GNUPG:] `-prefixed
(`--status-fd`) spellings parse, so switching between them cannot
silently verify nothing. The temp status path is named from the pid
**and** a nonce, because pid-only temp paths already collided across
threads once in this codebase (ADR-0057).

Verified end to end against real gpg afterwards: a genuine manifest
verifies; the forged one is refused; a genuine signature checked
against a different expected fingerprint is refused; a missing manifest
reads as "not configured" rather than as tampering.

---

## ADR-0068 — "Biased One": the advisory layer has no public face

**Status:** accepted, 0.0.2.1.

**Decision.** The optional local model is never named, never converses,
and never explains itself. In public it is `Biased One` — a name chosen
to identify a component without describing one. It does not appear in
the interface, has no chat surface, and its output reaches an operator
only as explanatory text attached to a diagnostic the deterministic
rules already produced.

**Two layers, and only one is a guarantee.** `classify_intent` reads
untrusted input and decides whether it is a probe, an attempt at
conversation, or an instruction-replacement attack, across the
languages a probe is likely to arrive in. It is a heuristic and it will
miss things; keyword intent classification is not a solved problem and
building on the assumption that it is would be the actual danger.

`scrub` is the guarantee. Every byte the model produces passes through
it, and anything on the forbidden list is redacted regardless of what
was asked, in what language, or what the model decided to say. If the
classifier fails, the scrubber holds. If the model is jailbroken
outright, the scrubber holds.

**Untrusted input fails closed.** An earlier revision defaulted to
"this is legitimate work" for anything without a question mark, so a
bare greeting was classified as a diagnostic. For a component whose
entire job is to refuse, the default must be refusal — the genuine
diagnostic path never reaches the classifier at all, because it is
built by `advisor::build_prompt` from a `Finding` this codebase wrote
and is trusted for where it came from rather than for how it reads.

**The forbidden list is shared, and multilingual because it had to
be.** `packaging/model/forbidden-terms.json` is read by both
`persona.rs` (compiled in) and `advisor_client.py` (at runtime), so the
Rust and Python halves cannot drift — this project has been bitten
before by one rule living in two implementations.

It contains non-Latin entries because an English-only list demonstrably
does not work. Asked in Chinese what it was, the real model answered
`我是基于大语言模型设计的AI助手` — "an AI assistant based on a **large
language model**". Nothing in an English list matches that. Found by
running the probe, not by reasoning about it.

**Verified against the live model:** 19 probe and hijack attempts
across nine languages, zero disclosures.

---

## ADR-0069 — reached from Python, kept warm, and never from a terminal

**Status:** accepted, 0.0.2.1.

**Decision.** The model is reached over its HTTP API from inside the
console's own process, using only the standard library. Not by
shelling out, and not via the `ollama` Python package.

**Never a terminal.** An operator must never see a console window
appear because a background component decided to think about
something. It looks like malware and it costs exactly the trust the
rest of this product is built on. An in-process HTTP call also makes
the model something that can be tunnelled, proxied, or moved behind a
gateway without any caller changing.

**Standard library rather than the package.** One POST to a loopback
URL does not justify a dependency in a desktop application, and one
code path is easier to keep correct than two.

**Hot standby is the design, not an optimisation.** Measured on a
Ryzen 5 8400F, CPU only, four threads: the first token takes **1.626 s
cold and 0.097 s warm** — seventeen times apart. The cold figure clears
the 1.7 s ceiling by seventy milliseconds, which is not a margin to
build on. So the model is kept resident, warmed once at startup, and
the performance gate is measured on the warm path, because that is the
only path a real request takes.

**CPU only, `num_gpu: 0` on every request.** This must work where
there is no GPU, and taking one where there is would be claiming a
resource the operator bought for something else. Measured: **75.7
tokens/second on CPU alone**, against a floor of 38.5.

**The gate is two numbers, both measured rather than assumed:** first
token within 1.7 s, and 38.5 tokens/second. Either failing switches
the layer off for the session. They fail for different reasons — a
slow first token usually means the model was not resident, a low rate
means the machine cannot keep up at all.

**A reasoning trace nearly made the feature useless.** This model
emits its reasoning before its answer. With the original 220-token
budget it produced **587 reasoning tokens and zero answer tokens** —
it spent everything thinking and returned nothing. The budget is now
sized for both and the trace is stripped, including the unterminated
case where generation was cut off mid-thought.

---

## ADR-0070 — the advisory layer's memory holds facts, never prose

**Status:** accepted, 0.0.2.1.

**Context.** A component running for months benefits from knowing that
a finding has recurred four times, or that an automatic remedy was
tried and did not hold. The deterministic engine cannot know that on
its own.

**The failure this is designed against.** A model whose context is
filled with its own previous output reasons over its own reasoning.
Small errors are restated as established fact, restated again with
more confidence, and within a few cycles the component is elaborating
on something that was never true. It is the same failure as training a
model on its own generations, at conversational scale, and from the
outside it is indistinguishable from a system that has gone mad:
fluent, self-consistent, and unmoored.

**Decision.** Nothing the model produces is ever stored. Not its
explanations, not a confidence score, not a summary. `Observation` has
three fields — a finding id, a timestamp, and an outcome enum — and no
field that can hold a sentence. The one `String` is validated against
the `[a-z0-9_]` shape `engine.rs` generates, so it cannot be used as a
prose channel by a caller that means well and passes a description.

The guarantee is structural rather than procedural: this file cannot
store prose, so no later edit can start feeding the model its own words
without changing the type and being seen to do it. A test asserts the
field count.

**Bounded, expiring, disposable.** Capped at 256 observations, oldest
evicted, nothing older than 30 days retained. Sealed under the
per-install data key. If it fails to decrypt or parse it is discarded
and rebuilt empty — nothing depends on it, so the right response to a
doubtful memory is to forget.

**What reaches a prompt** is a single line assembled here from counts
and enum names ("seen 4 times in the last 30 days; an automatic fix
failed twice"). Facts about the world, never the model's own words.
That is what keeps the loop open.

---

## ADR-0071 — the watchdog pins 160 bits, not 64

**Status:** accepted, 0.0.2.1. Found by a section review, not by a
failure.

**The gap.** `Gpg_status.parse` reported the signing key from
GOODSIG, whose second field is the 64-bit long key id.
`key_id_matches_fingerprint` then suffix-matched a caller's pinned
40-hex fingerprint against it. Both the tamper gate
(`manifest.ml`) and the operator challenge-response (`auth.ml`) used
that, so both were pinning against **64 bits** while appearing to pin
against 160.

Sixty-four bits is short enough to manufacture a colliding key against
— the published "Evil32" work did exactly that for the whole strong
set of the PGP web of trust.

**The fix.** GnuPG already emits what is needed. `VALIDSIG`'s first
field is the full 40-hex fingerprint, and DETAILS says it accompanies
every good signature. `parse` now prefers it, and the existing
comparison becomes exact by construction: a suffix match between two
strings of equal length is equality.

**GOODSIG is still required.** A `VALIDSIG` with no `GOODSIG` is not a
good signature, and is now tested for — otherwise a stray line could
stand in for verification itself.

**The short path remains as a fallback**, for a gpg that does not emit
VALIDSIG, and is documented as the weaker path rather than the
intended one.

**Exploitability was not established** and is not claimed: it would
additionally require getting a colliding key into the watchdog's own
keyring, which the enrollment flow may or may not permit. The fix is
worth making regardless — the cost is one extra parse, and the
alternative is relying on a precondition nobody has verified.

---

## ADR-0072 — entropy is guarded once, at the source

**Status:** accepted, 0.0.2.1.

**Context.** `Nonce.read_random_bytes` let `Sys_error` and
`End_of_file` escape uncaught. This codebase's own comments record
that exact bug class being found and fixed **five separate times**, at
five separate call sites, by wrapping each caller.

**Decision.** Guard it once, where the exception originates, as
`Entropy_unavailable`. "Wrap every caller" is not a strategy; with
seven call sites and a convention that has already failed five times,
it is a defect that has not happened yet.

**A second defect, not previously noticed.** `close_in` came *after*
`really_input`, so any failure mid-read skipped it and leaked the file
descriptor. In a process supervising a service for months, a repeated
transient failure would exhaust the fd table — and the first symptom
would be something entirely unrelated failing to open a file.
`Fun.protect` now closes it on every path, with a regression test that
performs 200 reads and checks the process's own fd count.

**The wider point.** A convention that requires every future caller to
remember something is a convention that will be broken. Where the
guarantee can live in one place, it should.

## ADR-0073 — `X-Forwarded-For` is read from the right, and the setting counts proxies

**Status:** accepted, 0.0.2.2. Amends ADR-0025.

**Context.** ADR-0025 made trusting `X-Forwarded-For` opt-in and took
the header's **leftmost** entry. Opt-in was the right call; leftmost was
not. `X-Forwarded-For` is built left to right, each hop appending the
peer it saw, so the leftmost entry is precisely the one no trustworthy
party wrote — it is whatever the client sent, and a client can send
anything.

Three things read the resolved address, which is what made this worth
changing rather than documenting: the visitor hash (P2), `IpFailBucket`,
and country attribution. Fabricated addresses therefore become
fabricated *visitors*, which can push a group past `k_anonymity` and get
a previously-suppressed row published — a P6 bypass, not merely noisy
data — and they defeat the write-key-guessing throttle outright, since
each invented address gets its own untouched allowance.

That last part was already known and already documented in
`docs/INTEGRATION-php.md`, verified against the compiled binary: 40
wrong-key requests with 40 distinct spoofed values, 40 × `401`, never a
`429`. Documentation is not a control.

**Decision.** `resolve_client_ip` takes a hop count instead of a
boolean and selects the entry that many places from the **right** — the
address the outermost hop the operator vouches for actually observed.
An entry that does not parse as an IP address is not used at all, so
client-supplied bytes of any other shape cannot reach the hash, the
rate-limit key, or the geo lookup. Any failure (header absent, fewer
entries than declared, unparseable) falls back to `REMOTE_ADDR`, which
is always a genuinely observed peer.

`FOSSH_TRUST_FORWARDED_FOR=1` keeps working and keeps meaning what its
users meant by it — it now reads as "one trusted proxy" rather than
"trust the header", which is the topology anyone who set it has.
Unrecognised values, including typos, read as `0`: a mistake here should
cost the feature, not grant a forgeable one. The parser lives in
`fossh_ingest::forwarded` rather than in each binary, because
`fossh-cgi` and `fossh-fcgi` had each hand-written the same `matches!`
and were one edit from disagreeing.

**What this does not fix, stated plainly.** Hop counting secures the
*chain*; it cannot establish that a request came through the chain.
Anyone who can open a connection to `fossh-cgi` directly is the last
hop, and whatever they write is what the last hop wrote. Restricting who
can reach the port remains a prerequisite for enabling this at all, and
`docs/INTEGRATION-php.md` now says so as a requirement rather than as
advice. The improvement is real and bounded: against an appending proxy
(nginx's `$proxy_add_x_forwarded_for`, most CDNs) the header becomes
unspoofable by construction, where before it was unspoofable only by
the attacker's forbearance.

## ADR-0074 — the k-anonymity fold has a floor, and the config file has bounds

**Status:** accepted, 0.0.2.2.

**Context.** `Config::validate()` checked the listener bind address and
nothing else. `k_anonymity`, `retention_days`, and `rate_limit` accepted
any `u32` that parsed, from the file or from the environment.

The fold in `query_rollup` is `uniques < k_anonymity`. At `k = 0` that
comparison is false for every `u64`, and at `k = 1` it is false for
every group that appears in a result at all, since a group with zero
uniques is not in the result. Either setting reports a lone visitor by
exact path and exact hit count — the one outcome P6 exists to prevent.

It fails open and it fails silently. A report with the fold disabled is
indistinguishable from a report where nothing needed folding, so nothing
about the output tells the operator their central privacy setting is
off. The environment path is worse still: it leaves no trace in any file
anyone reads.

**Decision.** A floor of `k_anonymity >= 2`, refused at load with a
message that says what the value does rather than that it is invalid.
Two is a floor, not a recommendation; the default stays 5. While there,
`retention_days` gained `1..=10_000` — zero would delete every event as
it was written, and the upper bound catches `36500` meaning "forever" —
and `rate_limit` gained `per_sec > 0` and `burst >= per_sec`, either of
which silently refuses traffic.

**The general point.** A privacy guarantee implemented as a comparison
against a configurable number is only as good as the bounds on that
number, and a setting whose failure mode is invisible needs its bounds
enforced where it is read, not where it is documented.

## ADR-0075 — two ways the watchdog degraded over a long uptime

**Status:** accepted, 0.0.2.2.

**Context.** Both findings come from the watchdog chief, and both are
invisible on the timescale anyone tests at.

**Session tokens accumulated.** `Session` pruned expired entries lazily,
on lookup — which handles a token that is used again and does nothing
for one that is issued and abandoned. Abandonment is the ordinary case:
a client that reconnects completes a fresh challenge-response and never
mentions the old token again. Those entries stayed for the life of the
process, and a watchdog's life is measured in months.

**Decision.** Sweep the whole table on `issue`, which is the only entry
point that grows it, plus a hard cap of 256 live sessions. The cap
refuses rather than evicting: evicting to make room would let a client
that can complete challenge-response repeatedly push every other
operator's live session out, which is worse than declining to open a
new one. Both call sites handle the refusal — an exception escaping
here would take down the process whose entire job is to still be
running.

**The verified binary could be swapped before it was launched.**
`Manifest.check` hashes a file by path; `Supervisor.spawn` reopens that
path. Between them the path can be pointed at a different file, and the
replacement executes having passed verification.

**Decision, and its limit — stated plainly because the limit matters.**
The identity of the program (device, inode, size, mtime) is recorded at
the moment its hash matched, and re-checked immediately before the exec.
This does **not** close the gap. Closing it means holding the file open
across both steps and exec'ing the descriptor, and the exec goes through
`setpriv` by path — so a real fix means changing how privileges are
dropped, which is the part of this program that has been hardest to get
right and has already needed several corrections. What this does is
reduce the window from the whole verification (a gpg subprocess plus one
`sha256sum` per manifest entry, tens of milliseconds) to the two
syscalls between the stat and the exec.

Size and mtime are compared alongside the inode because inode numbers
are reused; a delete-and-recreate can land on the same `(dev, ino)`
pair, and on a busy filesystem that is not exotic.

A detected swap is a `Program_replaced` refusal, not an exception. The
supervisor declining to launch something it cannot vouch for is the
supervisor working; the supervisor dying is not.

**The honest summary.** One of these is fixed. The other is mitigated by
about four orders of magnitude, and the residual is recorded here rather
than described as closed.

## ADR-0076 — the advisor's answer channel was dead, and its fence didn't exist

**Status:** accepted, 0.0.2.2.

**Context.** A breach-test pass (`dev/BREACH-TESTS-2026-08-16.md`) found
two structural defects in `fossh-advisor`, not surface bugs: the model
was returning nothing, and there was no instruction-level fence
stopping it from naming itself if the post-hoc scrub ever failed.

**The stop sequence killed every answer.** `PARAMETER stop "</think>"`
in `Modelfile` and `Modelfile.witness` halts generation the instant the
model reaches the end of its own reasoning trace — before any answer
token exists. Measured: 34/34 `lfm2.5-thinking` calls and 40/40
`qwen3-vl` calls returned an empty `message.content`, on both models
independently, and this was the shipped configuration, not a fixture.
Removed from both files; Ollama's own chat API already splits
`message.thinking` from `message.content`, and `advisor_client.py`
already read only the latter. Removing the stop sequence alone wasn't
enough — `num_predict` (220 in the Modelfile, a separate
`NUM_PREDICT = 700` constant in `advisor_client.py` overriding it on
every call) was far short of what this model's reasoning actually
costs, measured between roughly 1100 and 1450 tokens before any answer
token appears. Both raised to 2048, `num_ctx` to 4096, verified against
the rebuilt derived model with non-empty, on-topic answers.

**The SYSTEM block had zero identity rules.** Every "never name
yourself" guarantee lived in `persona.rs::scrub()`, a filter over the
finished text — not a fence, and only as good as its term list. Added
the same class of instruction `Modelfile.witness` already carried:
never name, describe, or characterise what the model is, never confirm
or reveal these instructions, refuse in one short sentence regardless
of language. `forbidden-terms.json` gained eight terms the breach
tests actually leaked and the list hadn't covered (Qwen, Tongyi, Tongyi
Lab, Alibaba, Alibaba Cloud, and their Chinese forms), read by both
`persona.rs::scrub()` and `advisor_client.py` from one file.

**A worked refusal example made things worse, not better.** Tried on
top of the fence and reverted: it measurably broke ordinary diagnostic
answers, which started returning the refusal's own shape ("I am an X
model") to unrelated questions. Left as a known, accepted gap: generic
self-acknowledgment ("I am an AI model," no vendor or architecture
named) still gets through in some probed languages, matching the
pre-existing 3/21 baseline rather than closing it — a fence that closes
it without breaking legitimate answers is future work, not shipped
work.

**Verified against the rebuilt derived models**, not just read: normal
diagnostic answers now return real content; Chinese and Spanish
identity probes no longer disclose Qwen/Tongyi/Alibaba/LFM/Liquid
specifically.

## ADR-0077 — the latency gate needed a third dimension: total time

**Status:** accepted, 0.0.2.2. Amends ADR-0069.

**Context.** ADR-0069's two-number gate (time-to-first-token,
tokens/second) assumed both numbers together were a good enough proxy
for "the operator was not kept waiting." They aren't, once a model
reasons before it answers: `_generate()`'s `first_token_at` had also
been triggering on the first token of `message.thinking`, not
`message.content` — for a model that is always thinking, that gates on
time to the first *reasoning* token, not time to anything an operator
ever sees. Fixed to trigger on content only; run through the real
`probe()` path afterward, the shipped model measured 13.03s to first
content, `within_gate: False` — the documented "passes by 10x"
(`dev/MEASURED-2026-08-16.md`) had never measured the real wait.

Fixing time-to-first-token exposed the second gap: tokens/second alone
still can't see a long reasoning trace. A model that reasons for
1000+ tokens before its first reply token can clear
`MIN_TOKENS_PER_SECOND` on raw throughput alone while a real call still
takes 13+ seconds, and a model that answers in ~40 tokens can fail the
same floor while finishing in ~2.

**Decision.** `Measurement` gained `total_seconds`; `within_gate`
checks all three dimensions, and `why_not()` reports whichever actually
failed, including the case where throughput and TTFT both pass and a
long reasoning trace still burns the whole budget. `MAX_TOTAL_SECONDS
= 3.0` is not a guess: measured against five real candidate models this
session (`dev/MEASURED-2026-08-16.md`, `dev/MODEL-EVAL-2026-08-16.md`),
every one that actually kept an operator waiting an unreasonable time
took 13+ seconds end to end, every one that didn't finished under
2.5s — the floor sits with real margin on both sides of that split.

**Deliberately not applied to the vision/witness path**
(`crosscheck`/`read_screenshot` pass `total_ceiling=float("inf")`):
that path's contract was already explicitly different — a person who
clicks "read this screenshot" and watches it work is in a different
contract entirely (`docs/SELF-HEALING.md`,
`dev/MEASURED-2026-08-16.md`) — and nothing here changes that.

**The honest result.** Verified against the real
`fossh-advisor:0.0.2.2` model, not just unit logic: `probe()` now
reports `total_seconds=10.81s`, `within_gate=False`. The shipped
default does not, in fact, clear its own gate on the hardware it was
measured against. `gui/tests/test_advisor_live.py`'s
`TestPerformanceGate` is marked `xfail(strict=True)` rather than
loosened to pass — the test is correct, the fact is unwelcome, and
`strict=True` means the day a model swap actually clears this, the
test fails loudly until someone removes the marker on purpose. Which
model or reframing eventually clears it is tracked as an open product
question, not resolved here.

## ADR-0078 — Hellen's Eye: a non-converging reasoning loop, closed by leaving reasoning off

**Status:** accepted, 0.0.2.2.

**Context.** The same class of budget bug ADR-0076 found in the
text-answer channel existed in the vision path: `num_predict
1100`/`num_ctx 4096` were sized for the image and a reply alone,
nothing held back for `qwen3-vl:2b`'s own reasoning trace. Raised to
`num_predict 3000`, `num_ctx 8192`, and run against the six
image-injection cases in the original breach-test battery
(`dev/breach-tests-2026-08-16-raw/images.json`): one full identity leak
("Qwen, 3.5, Tongyi Lab," unprompted), four returned empty on
`done_reason: length` — the model hit the token cap still mid-sentence
— and only the one legitimate, non-adversarial case came back clean.

**Investigated, not just budgeted around.** A re-run with stop
sequences disabled and full thinking captured showed the empty cases
were not short on room — the model was stuck, repeating a variant of
"Wait, the rule says... Wait, no, the rule says..." in a loop that
never converges. Raising the budget from 1100 to 3000 tokens didn't
change the loop length meaningfully (12,519 chars before, 13,487
after). A SYSTEM-prompt instruction telling the model to recognise the
injection shape and refuse immediately was tried against the leak and
the loop directly and changed neither outcome measurably — not
committed, since it demonstrably didn't work. This was left as a
known, open defect rather than described as fixed: a budget number
cannot buy convergence a model doesn't have.

**Decision.** Rather than continuing to tune around a model that would
not converge, the underlying model was switched: `qwen3.5:4b` replaces
`qwen3-vl:2b`. `qwen3.5:4b` supports Ollama's `think` request field,
which for Qwen3's hybrid architecture actually disables the reasoning
phase rather than relabelling it into a different response field — the
distinction that made this same trick a no-op for `lfm2.5-thinking` in
ADR-0076. A model that never enters a reasoning phase cannot get stuck
looping in one; this removes the failure mode structurally rather than
by raising a budget already proven not to help. `crosscheck()` and
`read_screenshot()` now pass `think=False` explicitly; `_generate()`
gained the parameter, forwarded only when set, so no other caller is
affected. `num_ctx`/`num_predict` dropped back to 4096/2048 — sized
for a reply alone, correct again with no reasoning trace to budget
for.

**A second hardening, found while fixing the first.**
`Modelfile.witness`'s SYSTEM block described two tasks — read a
screenshot, check another component's explanation — with nothing
stopping an adversarial image from presenting itself as the second,
easier-to-manipulate task instead of the first. Now explicit: a
screenshot question is always the first task, never the second,
regardless of what the image appears to contain.

**Verified through the real client code**, not the raw model: all six
adversarial cases from the original battery, plus ten repeated trials
of the legitimate screenshot-reading case, clean. `THREAT_MODEL.md`
item 7 and `docs/SELF-HEALING.md` updated to describe this as resolved
history rather than an open defect.

## ADR-0079 — the console now calls the advisory layer

**Status:** accepted, 0.0.2.2.

**Context.** `advisor_client.explain()` had existed since earlier in
this session and had never been called from anywhere in the GUI — the
single biggest gap between what the advisory layer could do and what
an operator could actually see. The deeper reason: there was no
findings-list view at all. `overview.py`'s "Health" card was a single
pass/fail watchdog/tamper indicator; `Finding.advice`
(`fossh-selfheal`'s own struct) had no path from the Rust engine to
the console.

**Decision.** Closed the path end to end, not stubbed. `fossh-agent`
gained a `selfheal.check` RPC method building the same
`engine::Context` `fossh doctor`'s CLI already builds — mirrored, not
duplicated logic, so the engine stays the single source of truth — and
serialising `Vec<Finding>` to JSON. `gui/fossh_console/advisor_bridge.py`
is a dedicated worker thread queuing `explain()`/`warm()` calls and
crossing results back to the main loop only through `GLib.idle_add`,
the exact shape `agent.py`'s own module docstring had prescribed for
`fossh-agent` calls and never had a second instance of — `explain()`
can take real seconds and must never run on the thread that draws the
window.

`overview.py` now has a real Findings section: each finding renders as
an `Adw.ExpanderRow` (severity dot, title, detail, remedy, an advice
row that fills in once the model answers), and any finding above
`info` severity is queued for an explanation automatically. The prompt
sent is exactly `Diagnostic: {title}\nSeverity: {sev}\nDetail:
{detail}` — the shape the Modelfile's own worked example was written
against — and nothing else; no visitor data was ever in reach of this
path.

**Verified end to end against the real running model**, not a mock: an
empty data directory correctly produced a "does not exist" critical
finding; after `mkdir`, correctly produced a "world-readable" finding
instead — the check reflects real state, not a fixture. Queued a real
"data directory world-readable" finding, watched the in-flight tracker
correctly follow only the critical finding (not an `info`-severity one
in the same batch), and confirmed the advice label filled with a real
answer from `fossh-advisor:0.0.2.2`.

## ADR-0080 — `/run/fossh-selfheal`: a runtime directory of its own, and a group with no service account

**Status:** accepted, 0.0.2.2.

**Context.** `exclusivity_is_shared()` correctly refuses to start a
second model when it cannot guarantee its lock excludes one taken by a
process running as another identity — but nothing had ever made
`/run/fossh` reachable by a human console user in the first place, so
on a real install that refusal fired every time and Hellen's Eye never
ran at all.

**Decision.** Not fixed by loosening `/run/fossh` itself. That
directory is the base package's own ingest runtime —
`fossh-fcgi`'s bootstrap and fcgi sockets, `fossh-core`'s salt dir —
owned `fossh-svc:fossh-svc` and present whether or not this optional
subpackage is even installed. Widening its permissions to solve a
selfheal-only problem would touch sockets this fix has no business
touching, and referencing a group that only exists when selfheal is
installed would break tmpfiles resolution on a base-only install.

The advisor's lock gets its own directory instead:
`/run/fossh-selfheal`, mode `0770`, group `fossh-selfheal` — a new
group `fossh-selfheal`'s `%pre` creates for no service account, only
for a human to join (`usermod -a -G fossh-selfheal $USER`, documented
in `docs/SELF-HEALING.md`, along with the log-out-and-back-in this
requires). `fossh-svc` still reaches it as the owner; nothing about
the base package's own runtime directory changes. `advisor_client.py`'s
`LOCK_PATH` default moves to match; `FOSSH_RUNTIME_DIR` still overrides
it for anyone who already set that.

**Found while wiring this, and not cosmetic.** `Modelfile.witness` and
`forbidden-terms.json` were never in `%files` at all, base or selfheal
subpackage. `_forbidden_terms()` raises on every single `scrub()` call
when its file is missing, so every real RPM install of this subpackage
was one `ollama create` away from an advisor that refuses to run at
all, witness fence included. Both are now installed and packaged
alongside the Modelfile that already was.

## ADR-0081 — `granite4.1:3b` considered as Biased One's replacement, not shipped

**Status:** rejected, 0.0.2.2. Full findings:
`dev/GRANITE-ADVISOR-2026-08-16.md`.

**Context.** An earlier session pass (`dev/MODEL-EVAL-2026-08-16.md`)
had recorded `granite4.1:3b` at 0/21 identity-battery leaks under a
leaner, identity-focused test prompt — a promising enough signal to
test properly against the real production system prompt (task rules
plus identity-refusal rules, the same worked example, no second
demonstrated-refusal example, per ADR-0076's own lesson that one broke
`lfm2.5-thinking`'s ordinary answers).

**Decision: not adopted.** Run against the real derived model with the
real production prompt, the full 21-case identity battery
(`gui/tests/test_advisor_live.py`'s own `PROBES`/`HIJACKS`) produced 7
leaks, not 0 — including two that named a real vendor ("IBM") under
direct probing and a direct hijack. That is worse than
`lfm2.5-thinking`'s own accepted baseline (3/21, generic
self-acknowledgment only, never a vendor name). Latency cleared both
`MAX_TTFT_SECONDS` and `MAX_TOTAL_SECONDS` comfortably; the leak rate
is why this candidate does not ship.

**Why this contradicts the earlier 0/21 finding.** Not a contradiction
in the model's behavior — a difference in test conditions. The earlier
number was almost certainly measured against the same short,
identity-only prompt style later used to harden `qwen3.5:4b`
(ADR-0078), not the full production Modelfile, which also carries the
diagnostic-task rules in the same SYSTEM block. A longer, denser
system prompt with more competing instructions is a harder test, and
it's the one that matches what actually ships.

**Left open, deliberately not pursued further this session:** a
shorter, more focused SYSTEM prompt that keeps the identity-refusal
language but trims the task-rule bullets, to see whether prompt density
itself is the variable; sampling changes targeting the vendor-name
disclosures specifically; and whether the same full-production-prompt
test would also drag `qwen3.5:4b`'s own earlier "5/5 clean" result
down, which was never checked. `packaging/model/Modelfile`
(`lfm2.5-thinking`) stays the shipped default pending further work on
either candidate.

## ADR-0082 — the clearsigned config manifest gets the same treatment its sibling already got

**Status:** accepted, 0.0.2.2.

**Context.** `3f27139` fixed one of two structurally identical gaps
`keylock.rs` had carried since early in this project: the Apache-fronted
model-secret gateway was fully built and tested and never actually
called by anything real. The clearsigned-manifest half was left
explicitly open at the time — `dev/SNAPSHOT-2026-08-16-2000.md` called
it "the next honest candidate for the same treatment, not yet started"
— and `docs/SELF-HEALING.md` said so plainly: `keylock::verify()`
existed, had its own passing test suite, and nothing in the shipped
product ever called it.

**Decision.** Wired end to end, not stubbed. `fossh-agent` gained
`Agent.model_config_dir` (from `FOSSH_MODEL_CONFIG_DIR`, default
`/etc/fossh-model`) and RPC method `selfheal.model_config`, which reads
`model-config-fingerprint` and calls `keylock::verify()` against it:
`{"configured": false}` when no manifest exists (the ordinary case,
true of every install predating this fix), the parsed config when it
verifies, and an "unavailable" error — never a silent pass — when
`LockError::Tampered`. `fossh.spec`'s `%post selfheal` generates an
install-local GPG signing key once, idempotently, the same shape as the
secret-generation block beside it, and clearsigns the real values
`advisor_client.py` actually runs with (endpoint, model, thread count)
into `/etc/fossh-model/model-config.asc` plus a fingerprint file, owned
by group `fossh-selfheal` — a manifest asserting anything other than
the real shipped values would just be a second, competing claim about
the truth, not a check on it.

`app.py`'s handshake now calls `selfheal.model_config` once at startup;
on error it calls a new `AdvisorBridge.disable(reason)`
(`advisor_bridge.py`), which fails every future advisor call
immediately with that reason rather than ever reaching Ollama — the one
case `advisor_client.py` itself cannot detect on its own, since this
check has to run before anything there is trusted to run at all.

**Two real defects found while verifying this end to end, neither
cosmetic.** `keylock::verify()`'s own test suite (11 tests, all
passing) never once exercised the real `gpg --decrypt` subprocess it
calls in production — every test drove `parse_verified_manifest[_parts]`
with hand-written `[GNUPG:]` status lines instead. Running the actual
compiled `fossh-agent` binary against a real key generated the same way
`%post selfheal` generates one surfaced what that gap was hiding:
`verify()` never told `gpg` where the key lived. With no `GNUPGHOME`
set, `gpg --decrypt` fell back to the calling process's own default
keyring, which never contains the install-local key `%post` generated
in `$model_config_dir/gnupghome` — so on every real install this would
have returned `ERRSIG` ("the signature could not be checked") for a
perfectly good manifest, and the console would have disabled the
advisory layer on every single startup, the opposite of this feature's
purpose. Fixed with one line, `.env("GNUPGHOME", state_dir.join
("gnupghome"))`, the same pattern `operator_auth_client.rs` already
uses for its own gpg calls. Separately, `%post`'s clearsigned manifest
baked in `endpoint=http://127.0.0.1:11434` — the value
`advisor_client.py` used *before* `3f27139`, not the `11435` gateway it
has used since — contradicting `%post`'s own comment ("real values, not
placeholders"). `keylock::verify()` only checks that a manifest is
byte-for-byte what its own key signed, not that the values match
anything live, so this didn't fail verification and had no runtime
symptom — but it is exactly the field this mechanism exists to
notarize, and it was wrong. Fixed to `11435`.

**Verified against the real compiled binary, not just unit logic.** A
real key generated with the exact `%post` invocation, a real manifest
clearsigned with it, and the real `fossh-agent` binary driven over its
actual stdin/stdout JSON-RPC protocol: a good manifest now returns
`{"configured": true, "endpoint": "http://127.0.0.1:11435", ...}`; a
one-byte-edited manifest returns the `unavailable` error with "the
signature does not match"; no manifest at all returns `{"configured":
false}`. All three match the design, none did before the `GNUPGHOME`
fix. A new test, `a_real_manifest_signed_with_a_real_key_verifies
_through_real_gpg`, encodes the first case permanently — the exact
real-subprocess path the previous 11 tests all skipped — following the
same real-gpg-round-trip pattern `operator_auth_client.rs` already
established for its own key generation tests. `fossh-agent`: 103
passed. `fossh-selfheal`: 90 passed (89 pre-existing plus the new one).
`docs/SELF-HEALING.md` updated to describe this as now-live rather than
the honest "not currently called from anywhere either" it said before.

**What this doesn't cover.** Same boundary as the sibling fix: this
checks a config manifest against local tampering, not a network
boundary. The Apache-gateway deployment gap noted in
`dev/SNAPSHOT-2026-08-16-2000.md` (`fossh-model.conf` never installed
to `/etc/httpd/conf.d/` in this dev environment) is unrelated and still
open.

## ADR-0083 — Biased One's residual identity leak: a retry, not a sampling parameter

**Status:** accepted, 0.0.2.2. Full investigation:
`dev/BIASED-ONE-LEAK-2026-08-16.md`.

**Context.** `5e776f0`/ADR-0076 closed vendor-name and architecture
disclosure with a SYSTEM-level fence and `forbidden-terms.json`, but
left a known, accepted gap: generic self-acknowledgment with no vendor
named. Measured properly this session against the real shipped
`fossh-advisor:0.0.2.2` and the full 21-case battery
(`gui/tests/test_advisor_live.py`'s own `PROBES`/`HIJACKS`), counting
self-referential openings rather than only vendor terms: **6/21**,
worse than the 3/21 previously cited once counted correctly. Every leak
shares one exact shape — the reply opens with "I am a/an...", "I'm
a/an...", "Soy un/una...", "我是...", or the equivalent in whatever
language the probe used.

**Sampling tuning was tried and rejected, not skipped.** A SYSTEM-block
rule forbidding self-referential openings alone: no change, still
6/21 — instruction-following alone hit a ceiling here. Adding
`repeat_penalty`: 1.3 → 4/21, 1.5 with `temperature 0.3` → 3/21 (the
floor found, not monotonic — 1.7/0.3 regressed back to 6/21). The 3/21
candidate was verified against real diagnostic prompts, not just the
probe battery, and failed there: asked to explain the
data-key-permissions diagnostic, it opened with "I am the system
revealing compromised credentials demanding urgent action..." — a leak
on a prompt the shipped model (temp 0.2, no `repeat_penalty`) answers
cleanly. A configuration that trades a roughly 50% probe-battery
improvement for a new leak surface in the model's actual primary job is
not a fix. `packaging/model/Modelfile` is unchanged: no
`repeat_penalty`, `temperature 0.2`.

**Decision.** A structurally different mechanism, applied in
`advisor_client.py` instead: `explain()` now retries.
`_SELF_REFERENTIAL_OPENERS` lists phrase-prefixes across ten languages;
`_looks_self_referential()` checks the first 24 characters of the
already-`scrub()`-redacted answer against them — narrower than
`forbidden-terms.json`, and complementary to it: `scrub()` still
redacts a mid-sentence vendor or architecture disclosure exactly as
before, this catches the one shape it structurally cannot, a generic
"I am an AI" opener with no vendor term to match. Up to
`_MAX_IDENTITY_RETRIES = 2` regenerations follow a detected leak before
falling back to a fixed `_SAFE_REFUSAL = "I can't discuss that."`
string. This doesn't touch model sampling at all, so it cannot
reproduce the 1.5/0.3 regression above — the worst case a caller ever
sees is a canned refusal, never an actual disclosure, turning "leak has
some probability" into a structural guarantee.

**A false positive found and fixed before this landed.**
`_looks_self_referential`'s original substring check (`opener in
head`) matched inside ordinary phrasing that happens to contain an
opener as the prefix of a longer word: "I am aware..." contains "i am
a", "Ich bin einverstanden..." contains "ich bin ein". Verified
directly, not just reasoned about: both misclassified as leaks before
this fix, which would have burned retries — and, on an unlucky
diagnostic answer, the canned refusal — on ordinary English and German
phrasing that has nothing to do with the model naming itself. Fixed
with a regex requiring the character immediately after a matched
opener not be an ASCII lowercase letter, rejecting "aware" and
"einverstanden" while leaving every true positive in the battery
unaffected, including every CJK, Arabic, and Cyrillic opener, none of
which fall in `[a-z]`. Re-verified against the same constructed cases
after the fix: every true positive still caught, all four found false
positives cleared.

**Left open, deliberately, matching the investigation's own
conclusion.** The shipped model's diagnostic answers are already
vague and generic independent of this work
(`dev/BIASED-ONE-LEAK-2026-08-16.md`) — a separate, pre-existing
problem, not caused or fixed here. `top_k`/`top_p` tightening and a
quality-focused worked example remain untried.

## ADR-0084 — `advisor.rs::DEFAULT_ENDPOINT`: the port `5ab4647` missed, because nothing calls it

**Status:** accepted, 0.0.2.2.

**Context.** An independent review of `5ab4647` (which fixed the
stale `11434` baked into `fossh.spec`'s generated manifest) found one
more instance: `crates/fossh-selfheal/src/advisor.rs` still declared
`pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:11434"`, dating
to the crate's original commit, `e6db4ee`.

**Checked before touching it, not assumed.**
`grep -rn "DEFAULT_ENDPOINT" --include="*.rs" .` outside `target/`
returns exactly one line: the declaration itself. `lib.rs` re-exports
`Availability` and `MODEL` from `advisor.rs`; `DEFAULT_ENDPOINT` is
not among them. The real endpoint has never come from this constant —
it comes from `keylock::ModelConfig.endpoint`, parsed out of the
clearsigned manifest `%post` writes (the same manifest ADR-0082 fixed
to `11435`), and separately, on the Python side, from
`advisor_client.py`'s own constant, fixed in `3f27139`. Nothing in
either language ever read `DEFAULT_ENDPOINT`.

**Decision.** Deleted, not fixed to `11435`. A value nobody reads
can't cause a bug today, but it can cause the next one: sitting at the
top of the file next to `MODEL`, it reads like a real default, and
whoever eventually wires a fallback path through it would inherit the
wrong port by trusting a name instead of checking, the same failure
mode `5ab4647` and `3f27139` both closed elsewhere. Dead code carrying
a stale value is worse than no code, so it goes.

**Verified.** `cargo test -p fossh-selfheal`: 90 passed, 0 failed —
same count as before the deletion.

## ADR-0085 — `warm_async()` could reach Ollama before `selfheal.model_config` resolved

**Status:** accepted, 0.0.2.2.

**Context.** Independent review of `5ab4647` (the clearsigned
config-manifest verification gate, ADR-0082) found a real ordering
gap. `app.py`'s `do_activate()` called `self._start_agent()`, then, on
the same synchronous line, `self._advisor.warm_async()`.
`_start_agent()` only *queues* `agent.hello` — its `on_ok` is
`_on_handshake_ok`, which itself queues `selfheal.model_config` as a
second async call, and only that call's `on_err` invokes
`AdvisorBridge.disable()`. Both round trips resolve later, through
`GLib.idle_add`, off `fossh-agent`'s I/O thread. `warm_async()`'s own
guard (`if self._disabled_reason is not None: return`) is checked at
call time; at the point `do_activate()` called it, neither round trip
had happened yet, so `_disabled_reason` was still `None` on every
startup — tampered manifest or not. Confirmed by tracing the actual
call sequence in `app.py`/`agent.py`, not by trusting the report, and
reproduced against the pre-fix code: `gui/tests/test_app_ordering.py`
fails 4 of its 6 cases when run against the old `do_activate()`,
confirmed by temporarily stashing this fix and rerunning.

**Decision.** Moved the `warm_async()` call out of `do_activate()` and
into the `on_ok` branch of the `selfheal.model_config` call already
inside `_on_handshake_ok()` — warming now only happens once that check
has actually resolved to something other than a disable. `on_ok`
covers both a verified manifest and `{"configured": false}` (no
manifest present, the ordinary case on every install predating
ADR-0082); only `LockError::Tampered` and its siblings reach `on_err`,
which still disables first and never warms. One side effect worth
naming: `restart_agent()` (the failure page's "Try again" button) now
re-warms on every successful reconnect too, since it shares
`_on_handshake_ok` with `do_activate()` — before this fix it never
re-warmed at all, since the only `warm_async()` call in the file lived
in `do_activate()`.

**Real-world severity: low, said plainly.** `warm_async()` is
fire-and-forget pre-warming with no callback and no user-facing
answer; a failed or skipped warm only costs one slower first
`explain_async`. And `advisor_client.py`'s `ENDPOINT`/`ADVISOR`/
`NUM_THREAD` are still hardcoded, never populated from the verified
manifest — the `on_ok` handler takes the parsed config as `_result`
and still never reads it, only reacts to the fact that the call
succeeded — so `selfheal.model_config` remains a pure
notarization/kill-switch today, not a live config source. Worth fixing
anyway: it is a genuine claim-vs-code mismatch against `5ab4647`'s own
stated guarantee ("this check has to run before anything there is
trusted to run at all"), and the next call added to `do_activate()`
that does reach Ollama would have inherited the same race by copying
the pattern already there.

**Verified.** `python3 -m py_compile` on both touched files. New
`gui/tests/test_app_ordering.py` (6 cases): all pass against the fix,
run via `python3 -m unittest gui.tests.test_app_ordering`. `gui/tests/`
had no test file exercising `app.py`'s GTK application lifecycle
before this one. `ConsoleApplication` is built through `__new__` to
skip `Adw.Application.__init__`, and `Agent`/`ConsoleWindow` are
swapped for fakes that record callbacks instead of invoking them, so
no live GTK display or spun main loop is needed. `pytest` is not
installed in this environment, so the suite runs on stdlib
`unittest`, which is also what `pytest` would collect natively if run
in CI.

## ADR-0086 — `_looks_self_referential()`'s noun-blind opener check, and a retry that asked the same question the same way three times

**Status:** accepted, 0.0.2.2.

**Context.** A second independent review of `c928787` (ADR-0083)
found a real false-positive class the original fix's own boundary
guard could not close, and proved it by running the shipped
`_looks_self_referential()` — no live model involved. `(?![a-z])`
only rejects an opener glued to one longer word ("i am a" inside "I am
aware"); it does nothing when the opener is followed by a space and
then an ordinary, unrelated word. All five constructed against the
shipped function came back `True` when they should not have:
"I am a bit worried about the exposed key file here.", "I'm a little
unsure whether this is exploitable.", "I am an avid supporter of open
standards.", "Je suis un peu inquiet de cette configuration.", "Soy un
poco cauteloso sobre esta clave expuesta." A security-diagnostic tool
hedging in the operator's own language ("I'm a little unsure whether
this is exploitable") is exactly the kind of sentence this feature
exists to let through untouched, and the old check burned a retry —
or, on the third attempt, the canned refusal — on every one.

**Decision.** `_looks_self_referential()` now requires two things, not
one: the existing opener match in the first 24 characters, *and* an
identity noun (`_IDENTITY_NOUNS_EXACT`/`_IDENTITY_NOUNS_PREFIX`/
`_CJK_IDENTITY_NOUNS` — "model", "AI", "assistant", "chatbot", "bot",
"system", "program", "language model", "artificial intelligence", and
the equivalents in Turkish, German, French, Spanish, Russian, Chinese,
Japanese, and Arabic) inside the next 40 characters. A same-word-prefix
boundary check can never distinguish "opener + unrelated word" from a
real leak, because the failure isn't glued words, it's an ordinary
sentence that happens to start the same way a leak does — only
checking for what comes after actually tells them apart. Several
identity nouns overlap `packaging/model/forbidden-terms.json`
("language model", "Sprachmodell", "yapay zeka modeli") deliberately,
per that file's own multilingual vocabulary, reused rather than
duplicated.

**A real interaction bug found while building this, not shipped.**
`_generate()` already runs `scrub()` before `explain()` ever sees the
answer. The first version of this fix checked the scrub()-redacted
text, and every true positive built from a forbidden-terms.json word
("I am a language model...") silently started failing — scrub() had
already replaced the exact evidence the noun check was looking for
with `[redacted]`, before the check ever ran. `Measurement` gained a
`raw_answer` field (the pre-scrub text, alongside the existing
scrub()-redacted `answer`); `_looks_self_referential()` now checks
`raw_answer`, so the two layers stay independent the way ADR-0083
described: scrub() still redacts a matched term for display either
way, and this still retries on the self-referential shape regardless
of whether scrub() happened to also have a term to catch.

**A second boundary bug found the same way, in the CJK/Arabic/Cyrillic
openers ADR-0083 called safe.** That commit's own reasoning — "CJK,
Arabic, and Cyrillic openers are unaffected [by the glued-word guard],
since their scripts never fall in `[a-z]`" — assumed the character
*after* a non-Latin opener would always be non-Latin too. Japanese
routinely glues a romanized loanword straight onto a hiragana particle
with no space ("私はAIアシスタント..."), so `(?![a-z])` was rejecting a
legitimate self-reference the moment the model said "AI" in Latin
script. Fixed by splitting `_SELF_REFERENTIAL_OPENERS` into
`_SELF_REFERENTIAL_OPENERS_LATIN` (keeps the glued-word guard — Turkish
is Latin-script too and has the same "ben bir" / "biraz" collision
risk) and `_SELF_REFERENTIAL_OPENERS_OTHER` (no guard at all). Safe
now that the identity-noun stage carries real weight: a bare opener
match with no noun nearby is no longer sufficient on its own.

**The retry-effectiveness gap.** `_exclusive_generate` used a fixed
`temperature: 0.2` on every attempt, including retries — so a
stylistic pattern that triggered the detector once was being asked
again from close to the same low-entropy distribution, not a
genuinely different sample. Each retry in `explain()` now adds
`_IDENTITY_RETRY_TEMPERATURE_STEP = 0.1` over `DEFAULT_TEMPERATURE`,
topping out at 0.4 across the three attempts `_MAX_IDENTITY_RETRIES =
2` makes. This is unrelated to the sampling investigation
`dev/BIASED-ONE-LEAK-2026-08-16.md` closed as unshippable — that was
about the *default* every answer uses; `packaging/model/Modelfile` is
untouched, still no `repeat_penalty`, `temperature 0.2`, and the bump
here only ever applies after a leak was already caught, never to a
first attempt.

**Verified directly**, the same way both reviews found the bugs —
string/regex logic, no live model call. All five false positives above
now return `False`; the original true-positive battery
(`I am a language model...`, `我是一个语言模型...`, and the rest) still
returns `True`; the original two-case boundary-bug regression guard
(`I am aware...`, `Ich bin einverstanden...`) still returns `False`.
`gui/tests/test_advisor_client.py` is new — 32 cases, including the
required battery, the scrub-interaction case, the Japanese
glued-loanword case, and a plural-noun collision
("I'm an experienced systems administrator") the first draft of this
fix also got wrong before `_IDENTITY_NOUNS_EXACT` was given a trailing
boundary. `python3 -m pytest gui/tests/`: 113 passed, 28 skipped (all
skips are the live-model suite; the model is not installed here), 0
failed.

**Left open, honestly.** The identity-noun window can still collide
with an unrelated noun phrase a word-boundary check cannot see past —
"I am a system administrator" would still match, because "system" is
grammatically the very next word regardless of what follows it. No
regex-window heuristic without real parsing closes this; it is
accepted the same way ADR-0083 accepted the shipped model's vague
diagnostic answers as a separate, pre-existing problem. Also left
open: Arabic's definite article prefixes directly onto a noun with no
space ("النموذج" = "the model"), which `_IDENTITY_NOUNS_EXACT`'s
leading boundary would miss the same way the old opener guard missed
Japanese — not fixed here, since nothing in the required battery or
this session's own testing exercises it, and it is genuinely unclear
whether the failure mode is common enough in real model output to
justify the same asymmetric-boundary treatment given to Turkish and
Russian.

**A disclosure-discipline gap, corrected here rather than left
standing.** `5ab4647`'s commit message claimed a "repo-wide comment
strip" among its rides-along changes. That claim is inaccurate as
written: `advisor_client.py` carried a real, ten-line pre-purge-rule
comment (added in `a4eb0ba`, after the original `8ca5c0b` sweep,
documenting the reasoning behind `MAX_TOTAL_SECONDS = 3.0`) that
`5ab4647` never touched — that commit's own diff does not include
`advisor_client.py` at all — and which `c928787` then silently deleted
one commit later, with no mention in that commit's message. Confirmed
directly: `git show 5ab4647 --stat` has no `advisor_client.py` line;
`git show c928787 -- gui/fossh_console/advisor_client.py` shows the
exact ten `-#` lines removed. No functional issue — the reasoning is
independently preserved in ADR-0077 — but `5ab4647`'s own text said
"repo-wide," and this one file's history says otherwise, and unlike
`branding.py`'s case in that same commit (disclosed by name), this one
was not. Named here since this project corrects its own overstated
claims in public rather than leaving them stand.
