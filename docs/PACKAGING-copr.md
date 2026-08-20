# Publishing foSSH to Fedora Copr

This is a maintainer document: how `fossh` gets built and published on [Fedora Copr](https://copr.fedorainfracloud.org/), not how an end user installs it (see the project README for that, once a Copr repository actually exists — it doesn't yet). Written for whoever holds the `s0aptile` Copr account, not a general contributor guide.

## Naming, up front

The Copr project is `s0aptile/fossh` — owner `s0aptile`, project `fossh`, matching the RPM's own `Name: fossh` in `packaging/rpm/fossh.spec`. Use `s0aptile` here specifically, not the `$0aptile` byline form: Copr project owners are Fedora Account System (FAS) usernames, which are alphanumeric/underscore only and won't accept `$`. See `PUBLISH.md` and the project's identity-hygiene notes for the fuller distinction between the two forms — this is the one case where only `s0aptile` is even a valid choice, not just the preferred one.

## Prerequisites

1. A Fedora Account System (FAS) account under `s0aptile`, with Copr access enabled (first login to copr.fedorainfracloud.org via FAS does this).
2. `copr-cli` installed (`sudo dnf install copr-cli`) and configured: download the API token from your Copr user settings page (`Settings` → `API`) and save it to `~/.config/copr` as that page instructs. That file holds a real credential — treat it like any other private token, never commit it, and it has no business anywhere in this repository (matches `PUBLISH.md`/`private-onlyauthor/`'s existing private-material handling, even though it lives outside the repo entirely).

## Creating the project (one-time)

```
copr-cli create fossh \
  --chroot fedora-44-x86_64 \
  --chroot fedora-rawhide-x86_64 \
  --description "Privacy-preserving, embeddable telemetry. Self-hosted, no third-party data path, k-anonymous." \
  --instructions "Open Alpha: interfaces may change between releases. See THREAT_MODEL.md."
```

Add more `--chroot` flags for additional Fedora releases/architectures as they become real support targets — this project's own glibc-floor design (`§2.5`) means a broader chroot list is a packaging decision, not a code one.

## Version scheme and the epoch — read before pushing a build

Packages are `0.0.2.x`, where `x` is a revision counter bumped by
`scripts/set-revision.sh`. Never edit a version by hand; that script
updates all nine places at once, and the two that are easy to forget
(the tarball prefix `%global srcversion`, and the derived model tag
that `advisor.rs` asserts against the Modelfile) will fail the build
rather than drift.

**The epoch matters here more than anywhere else.** `0.0.2.x` is
numerically *lower* than the retired `0.1.3`, so `Epoch: 1` in the spec
is what makes `dnf` see an upgrade instead of a downgrade. A Copr repo
is exactly where that shows up: anyone who enabled this repo during the
0.1.x line and runs `dnf upgrade` gets nothing at all without it, with
no error to explain why. Do not remove the epoch, and do not lower it.

**Four packages come out of one SRPM now**, not two:

| Package | Arch | Chroots |
|---|---|---|
| `fossh` | x86_64 | all |
| `fossh-console` | noarch | all |
| `fossh-selfheal` | noarch | all |
| `fossh-watchdog` | x86_64 | Fedora only (needs `ocaml-ctypes-devel`, absent from EPEL) |

`fossh-console` and `fossh-selfheal` are `noarch` and build everywhere,
including the EPEL chroots, so the EPEL story is no longer "core only"
— it is "everything except the watchdog".

**EPEL/RHEL-family scope: revisited 2026-08-06, real answer below — this is no longer an open question, it's a documented, partial, currently-blocked state.** The original spec (`§3.11`) always scoped this RPM at "Fedora/RHEL family"; only Debian/`apt` packaging was ever deferred (`§6`). `epel-9-x86_64` and `epel-10-x86_64` chroots have been added to the live `s0aptile/fossh` project (`copr-cli modify s0aptile/fossh --chroot fedora-44-x86_64 --chroot fedora-rawhide-x86_64 --chroot epel-9-x86_64 --chroot epel-10-x86_64` — `copr-cli modify --chroot` replaces the *entire* chroot list per invocation, not additive, so always pass every chroot you want to keep, not just the new ones). Real builds have been attempted against both. Neither has produced an installable package yet — see "EPEL/RHEL-family build status" below before telling anyone to `dnf copr enable` these.

RHEL itself isn't directly buildable-against without a subscription; Copr's `epel-9-x86_64`/`epel-10-x86_64` chroots build against CentOS Stream 9/10 + EPEL as a real stand-in (confirmed from a real build's own `Config(centos-stream+epel-10-x86_64)` log line) — the resulting package is what actually installs on real RHEL 9/10 and RHEL-compatible rebuilds (Rocky, Alma) via `dnf copr enable s0aptile/fossh epel-9-x86_64` once a build actually succeeds, same as any other EPEL-hosted Copr package. `rhel-9-x86_64`/`rhel-10-x86_64` chroots also exist in Copr's own `list-chroots` output but need a Red Hat/CentOS build-system entitlement this project doesn't have — `epel-9-x86_64`/`epel-10-x86_64` are the right chroots for an unprivileged Copr account, not a gap.

**One SRPM, multiple chroots — confirmed, not assumed.** `dist/fossh-0.0.2.2-1.fc44.src.rpm`'s filename says `fc44` because that's this dev machine's own local `%dist` at the moment `scripts/build-release-rpm.sh` ran `rpmbuild -bs` — but the *spec bundled inside that SRPM* still has `Release: 1%{?dist}` with `%{?dist}` unexpanded (confirmed by extracting it with `rpm2cpio ... | cpio -idm` and reading the spec directly), not baked to a literal `.fc44` string. That means the exact same SRPM can be submitted to any chroot via `copr-cli build s0aptile/fossh --chroot <chroot> <srpm>` and Copr's build backend re-evaluates `%dist` inside that chroot correctly — real build logs back this: the same source SRPM came back tagged `fossh-0.1.3~alpha.1-1.el9.src.rpm` on `epel-9-x86_64` and `...-1.el10.src.rpm` on `epel-10-x86_64`. `scripts/build-release-rpm.sh` does not need a per-distro variant; the `fc44` in the filename is cosmetic, not a real constraint.

### Item 3 (the EVP_MAC link failure) is fixed — 2026-08-15

**Everything in the 2026-08-07 section below is preserved as written,
but item 3 is no longer accurate and item 4 has not been retested.**
Read this first.

`scripts/build-release.sh` now hands the linker the system
`libcrypto.so` as an explicit file argument, found via `pkg-config`,
so SQLCipher's `EVP_MAC_*` calls resolve against real OpenSSL before
BoringSSL's colliding `libcrypto.a` is ever reached. A full
`scripts/build-release-rpm.sh` on Fedora 44 now produces all four
packages plus the SRPM:

    dist/fossh-0.0.2.2-1.fc44.src.rpm
    dist/fossh-0.0.2.2-1.fc44.x86_64.rpm
    dist/fossh-console-0.0.2.2-1.fc44.noarch.rpm
    dist/fossh-selfheal-0.0.2.2-1.fc44.noarch.rpm
    dist/fossh-watchdog-0.0.2.2-1.fc44.x86_64.rpm

Not just link-clean — functionally correct. `fossh-fcgi` resolves
`libcrypto.so.3` dynamically, and a freshly created database opens with
sixteen random bytes where an unencrypted SQLite file would read
`SQLite format 3`, which is SQLCipher genuinely running through that
OpenSSL rather than silently degrading.

**What is still open:**

- **No Copr build has been attempted since the fix.** The last
  submission predates it. Fedora chroots are expected to pass now; that
  is an expectation, not a result, and this file should not claim
  otherwise until a build number can be cited here.
- **Item 4 (EPEL 9's stale Rust) is untouched by this.** It fails before
  compilation on an MSRV check and needs Copr's EL9 buildroot snapshot
  to catch up to CentOS Stream's own `rust` 1.97.
- **The advice below still holds:** do not tell anyone to
  `dnf copr enable` any chroot until a build succeeds there.

One hardening from this: the `libcrypto.so` lookup used to warn and
carry on when `pkg-config` could not answer, which produced the
`undefined reference to EVP_MAC_fetch` failure several minutes later
with nothing pointing at the cause — that is how this was originally
recorded as an unexplained Rust-level regression. It now falls back to
well-known library paths, and failing that stops with a message naming
the missing build dependency. `pkgconfig` was added to the spec's
`BuildRequires` so the question does not arise in a chroot.

### EPEL/RHEL-family build status (as of 2026-08-07)

**The `ocaml-ctypes-devel` blocker below (item 2) is fixed as of `packaging/rpm/fossh.spec` Release 2** — the spec now builds two RPMs from one SRPM: a base `fossh` package (pure Rust — `fossh`, `fossh-cgi`, `fossh-fcgi`, `fossh-tui`, the SELinux module — buildable everywhere) and a `fossh-watchdog` subpackage (the OCaml watchdog, `ocaml-ctypes-devel` and all) gated behind `%if 0%{?fedora}` in every section that touches it (`%package`, `BuildRequires`, `%build`, `%install`, `%files`, scriptlets). On EPEL/CentOS Stream chroots `%fedora` is unset, so the entire watchdog subpackage — declaration, dependencies, and build steps — is skipped, not merely excluded from the file list. **Confirmed for real, not by inspection**: three fresh Copr builds submitted against the same SRPM (`fossh-0.0.2.1-1.fc44.src.rpm`) — `epel-9-x86_64` (build [10835124](https://copr.fedorainfracloud.org/coprs/build/10835124)), `epel-10-x86_64` (build [10835127](https://copr.fedorainfracloud.org/coprs/build/10835127)), `fedora-44-x86_64` (build [10835128](https://copr.fedorainfracloud.org/coprs/build/10835128)). Both EPEL builds' own `root.log`/`builder-live.log` show `ocaml-srpm-macros` installed (a generic macro package, unrelated) and **zero** occurrences of `ocaml`, `ocaml-dune`, `ocaml-ctypes-devel`, `ocaml-findlib`, or `jq` anywhere in the dependency-resolution or install log — the exact packages that used to be requested and fail to resolve are now never even asked for. `%files` for base+watchdog together, cross-checked against the last known-good full single-package build's own `rpm -qlp` output (`dist/fossh-0.1.3~alpha.1-1.fc44.x86_64.rpm`, built before this split), accounts for every one of that build's 19 paths with none missing and none duplicated.

Two *new*, separate, real blockers surfaced by these same three builds — both discovered here for the first time, neither caused by the subpackage split (the split doesn't touch `%build`'s call to `./scripts/build-release.sh`, and both reproduce identically whether or not the watchdog subpackage is even attempted), and **neither yet fixed**:

3. **A real, previously-undiscovered Rust-level regression, affecting every chroot including Fedora.** All three builds that got far enough to actually link (`epel-10-x86_64`, `fedora-44-x86_64`; `epel-9-x86_64` didn't get this far — see item 4) fail identically:

   ```
   undefined reference to `EVP_MAC_fetch'
   undefined reference to `EVP_MAC_CTX_new'
   ... (EVP_MAC_*, EVP_CIPHER_get_*, EVP_MD_get_size)
   collect2: error: ld returned 1 exit status
   error: could not compile `fossh-fcgi` (bin "fossh-fcgi") due to 1 previous error
   ```

   Root cause: `scripts/build-release.sh` unconditionally builds with `--features fossh-fcgi/quic,fossh-agent/quic` (§3.4's QUIC channel, needed so the shipped binaries can actually talk to the watchdog), which pulls in `fossh-ipc` → the `quiche` crate → `boring-sys`, statically linking a vendored BoringSSL into `fossh-fcgi`/`fossh-tui`. Those same two binaries also link `fossh-store`, which (§3.8, data-at-rest encryption) now builds with rusqlite's `bundled-sqlcipher` feature — SQLCipher's C code calls OpenSSL 3.x's provider-era EVP_MAC/`EVP_*_get_*` API, expecting to resolve `-lcrypto` against the *system* OpenSSL. BoringSSL is a pre-3.0-API fork that never implemented the EVP_MAC provider interface at all, and its static archive ends up ahead of system `libcrypto` in link order — so those symbols go unresolved. This is not new to EPEL: reproduced identically on `fedora-44-x86_64` (4m18s build, real crate compilation, real link failure) and on this maintainer's own Fedora dev machine via `sh scripts/build-release-rpm.sh`. `dev/DURUM.md`'s own §3.8 entry ("The RPM built for §3.11 predates this change — rebuilding it to pick up the new code is a follow-up, not done as part of this entry") confirms this exact combination — the quic-enabled release build plus `bundled-sqlcipher` — has never actually been through a full release build before; this is genuinely new, not a known/tracked gap. **Out of scope for packaging work to fix** — it needs a Rust-level decision (e.g., linking SQLCipher against BoringSSL instead of system OpenSSL, dropping one of the two dependencies from the affected binaries, or forcing link order) that this pass didn't make.

4. **EPEL 9 specifically (not EPEL 10) also currently fails earlier, for an unrelated third reason**: Copr's `epel-9-x86_64` chroot resolves `rust`/`cargo` `1.92.0-1.el9`, below this workspace's `rust-version = "1.97"` pin — Cargo's own MSRV gate refuses outright (`error: rustc 1.92.0 is not supported by the following packages: ... requires rustc 1.97`) before any compilation, let alone linking, happens. This is very likely a stale Copr chroot buildroot snapshot rather than a genuine EPEL 9 gap: a direct `dnf repoquery` against CentOS Stream 9's own AppStream mirror shows `rust`/`cargo` `1.97.1-1.el9` really is available there (matching the pin exactly, same as EPEL 10, which resolved a new-enough version and got past this check with no changes needed). `epel-10-x86_64`'s own build did not hit this at all — it reached the same item-3 link failure instead, several minutes further into the build.

**Net effect, precisely stated:** the split does exactly what it was built to do — the original `ocaml-ctypes-devel` blocker is gone, proven with real builds, not assumed. But as of this writing, item 3 blocks a fully green build on *every* chroot, Fedora included, and item 4 additionally blocks EPEL 9 specifically even once item 3 is fixed. **Don't tell an end user to `dnf copr enable s0aptile/fossh epel-9-x86_64` (or any other chroot) yet** — there is still no successful build of this version to install anywhere, for reasons that have moved from "EPEL-only, structural" to "everywhere, a real Rust-level bug plus one Copr chroot-freshness issue." The `epel-9-x86_64`/`epel-10-x86_64` chroots stay enabled on the live project; re-attempting a build once item 3 lands a fix costs nothing, and item 4 may simply resolve itself once Copr's own EL9 buildroot snapshot catches up to CentOS Stream's AppStream, though that hasn't been confirmed by a retry.

The raw `checkmodule`/`semodule_package` SELinux module toolchain this project uses (`packaging/selinux/`, no M4 interface-library macros) resolves and installs cleanly on both EPEL chroots, same as before — SELinux tooling was never the blocker at any point in this investigation. The SELinux module itself (`packaging/selinux/fossh.te`) confines `fossh_cgi_t`/`fossh_fcgi_t` only — both base-package binaries, no watchdog-specific domain exists — so it ships in the base package, not gated to Fedora, and builds/installs identically on EPEL.

The description/instructions text above should stay in sync with `PUBLISH.md`'s own copy-paste sheet — that file is the authoritative source for public-facing project copy, this command shouldn't drift into saying something different.

## Building an SRPM to submit

Copr builds from an SRPM (or a spec + sources it can turn into one), not from a plain `git clone`. Use this project's own release-build script rather than a bare `rpmbuild`, for the same identity-hygiene reasons it already exists:

```
sh scripts/build-release-rpm.sh
```

This produces both a binary RPM and an SRPM under `dist/` (via a real `rpmbuild -ba`, `_topdir`/`_buildhost` overridden so neither this machine's real path nor hostname leaks into the package metadata — see that script's own header comment and `DECISIONS.md` ADR-0054 for why that matters). The SRPM is the one Copr actually wants.

## Submitting a build

```
copr-cli build s0aptile/fossh dist/fossh-0.0.2.2-1.fc44.src.rpm
```

`copr-cli build` accepts a local SRPM path or a URL to one — a local path is simpler here since the SRPM is already sitting in `dist/` from the step above. Watch the build at `copr-cli watch-build <build-id>`, or check `https://copr.fedorainfracloud.org/coprs/s0aptile/fossh/builds/`.

## Real open questions, not yet verified — check before the first real submission

This project's own honesty-about-gaps convention (see `THREAT_MODEL.md`'s "Alpha caveats") applies here too. Two things this guide asserts by pattern-matching against how Copr generally works, not because they've been confirmed against this exact package yet:

- **Network access during the build.** Copr's build workers run in Mock chroots; `scripts/build-release-rpm.sh`'s own header notes this project has "no `--offline`/vendored-dependency setup yet... this works today only because the build environment's cargo registry cache is already warm" — i.e., a real network-isolated build (Koji, or a Copr chroot with networking disabled) would currently fail fetching crates.io dependencies fresh. Copr chroots can have networking enabled per-project (`copr-cli create --enable-net on ...` or the equivalent web-UI toggle) — turn it on for now, and treat properly vendoring dependencies (`cargo vendor` + a bundled `.cargo/config.toml`, already flagged as the real fix under `§3.10` supply-chain hardening) as the follow-up that removes the need for it, not something to solve as part of a first Copr submission.
- **Whether Fedora's own `rust`/`cargo`/`ocaml`/`ocaml-dune` RPMs actually satisfy this spec's `BuildRequires` without `--nodeps`.** Every real build so far, on this dev machine, has used `--nodeps` specifically because Rust here is rustup-managed, not the system package — see `dev/DURUM.md`. **Resolved (2026-08-06), confirmed against a real Copr build, not just repoquery:** an actual `fedora-44-x86_64` build got well past `BuildRequires` resolution and into a live `cargo build` (dependency crates downloading and compiling, `boring-sys v4.22.0` among them) — `rust`/`cargo`/`ocaml`/`ocaml-dune` all resolved and satisfied this spec without `--nodeps`, exactly as the repoquery-based prediction below said they should. The build still failed, but past this concern entirely, on something unrelated: `boring-sys`'s own build script shells out to `git init` (BoringSSL's own vendoring step, one layer under the `§3.4` QUIC feature), and Copr's minimal Fedora buildroot doesn't carry `git` by default — a real, reproduced, different failure (`error: failed to run custom build command for boring-sys v4.22.0`), already addressed with an explicit `BuildRequires: git` line in `fossh.spec`. (Original repoquery evidence, still true: `dnf repoquery --available rust cargo` against a real Fedora 44 system shows `rust`/`cargo` 1.97.1 in the Updates repo, exactly satisfying the workspace's `rust-version = "1.97"` pin in `Cargo.toml`.)

Neither of these blocks getting a Copr project *created* and a first build *attempted* — they were the likely first real failures on Fedora chroots, both now resolved one way or another; see "EPEL/RHEL-family build status" above for the equivalent, still-open picture on EPEL chroots specifically.

## Real build status as of 0.0.2.2, six real submissions in — one chroot green, four blocked on a named, tracked, unfixed cause

**`epel-10-x86_64` builds clean.** Confirmed six separate times
(builds 10882464 through 10882767), same result every time regardless
of which fix was being tested. `dnf copr enable s0aptile/fossh
epel-10-x86_64` is honest to publish and to tell an end user, today.

**`fedora-44-x86_64`, `fedora-45-x86_64`, `fedora-rawhide-x86_64`, and
`epel-9-x86_64` are not green, and should not be enabled or offered
to anyone until one of them is.** All four fail `%check` on
`gpg: failed to start gpg-agent '/usr/bin/gpg-agent': General error`
— the local watchdog/agent test suite spawning real `gpg` subprocesses
that need a live agent, which cannot start inside Copr's real Mock
buildroot for a reason six real, distinct fix attempts did not
resolve (a pipe-read ordering bug, a missing `GNUPGHOME` environment
variable, and forced-sequential test execution on both Rust and
OCaml — each one a real fix, none of them the actual cause; full
investigation trail in `DECISIONS.md` ADR-0091 through ADR-0096).
Every local reproduction attempt — a capability-matched rootless
container, CPU-throttled parallel execution, the full unfiltered
workspace test suite — passed clean; only Copr's real infrastructure
reproduces this. Real diagnosis needs `mock --shell` against Copr's
own real buildroot, genuine interactive access this investigation
never had (needs `dnf install mock` and root). Until someone with
that access closes it, these four chroots stay enabled on the live
project (free to re-attempt) but undocumented as installable.
