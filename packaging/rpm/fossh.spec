# foSSH RPM spec (chapter §3.11). No `rust2rpm`/Fedora Rust-packaging
# macros used — this build environment doesn't have that package, so
# %%build/%%install are plain `cargo build --release --workspace` plus
# manual `install -D`, which is a valid, common alternative to the full
# Fedora Rust packaging guideline flow, just less automated.
#
# Version note: `%%{srcversion}` (hyphenated, matches Cargo's own
# `0.2.0-alpha.1`) names the source tarball/directory; `%%{version}`
# (tilde form, RPM's own prerelease convention — sorts *before*
# `0.1.3` with no suffix, which is the ordering an alpha needs) is what
# actually appears in the built package's metadata. Kept separate so
# neither has to deal with the other's separator character.
%global srcversion 0.2.0-alpha.1
# Cargo's own release profile (strip = true) already strips every
# binary before %%install even runs; there's no meaningful debug info
# left for rpm's own automatic debuginfo/debugsource extraction to
# find. Left enabled, that step started failing outright once
# scripts/build-release.sh's --remap-path-prefix was added (rpm's
# find-debuginfo tries to resolve the remapped source paths back to
# real files on disk to build the debugsource package, and a remapped
# path like /build/fossh/... isn't a real path during packaging) —
# disabling it is the correct fix, not a workaround: there was never
# anything genuine for it to package once Cargo's own strip already ran.
%global debug_package %{nil}

Name:           fossh
Version:        0.2.0~alpha.1
Release:        2%{?dist}
Summary:        Privacy-preserving, embeddable telemetry (self-hosted analytics)

License:        MIT
URL:            https://github.com/s0aptile/foSSH
Source0:        %{name}-%{srcversion}.tar.gz

# --- Subpackage split (Release 2): this spec now builds two RPMs from
# one SRPM — the base %%{name} package (pure Rust, buildable and
# installable on Fedora *and* EPEL/RHEL 9/10) and an optional
# `%%{name}-watchdog` subpackage (needs Fedora's ocaml-ctypes-devel,
# not packaged for EPEL — see docs/PACKAGING-copr.md's "EPEL/RHEL-
# family build status"). Every %%if 0%%{?fedora} block below, in
# BuildRequires, %%build, %%check, %%install, the scriptlets, and
# %%files, is part of that same split — skip watchdog entirely rather
# than let the base package's build fail alongside it. `%%fedora` is
# unset (0) on EPEL/CentOS Stream chroots, set on real Fedora ones —
# confirmed from real Copr build logs (`Config(centos-stream+epel-
# 10-x86_64)` for the former).

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc
BuildRequires:  git
BuildRequires:  openssl-devel
# The `openssl` CLI itself, not just -devel: `fossh-admin::tls_identity`
# (core's §3.4 mTLS identity, shelled out to via a hardcoded
# `/usr/bin/openssl`) has its own real `cargo test` suite that
# %%check's `cargo test --workspace` always runs, unconditionally —
# not gated behind the `quic` feature, so this matters on every
# chroot. Fedora's default buildroot happens to already carry
# `openssl` as a dependency of something else, so this was invisible
# there; a real `epel-10-x86_64` Copr build reproduced the gap
# directly (`Generate("No such file or directory (os error 2)")`,
# every `tls_identity` test failing the same way) — `openssl-devel`
# does not pull in the `openssl` binary package as a hard dependency
# on RHEL-family the way it effectively does on Fedora.
BuildRequires:  openssl
BuildRequires:  checkpolicy
BuildRequires:  policycoreutils
BuildRequires:  systemd-rpm-macros
# selinux-policy itself (not just -devel) is what actually ships
# /usr/lib/rpm/macros.d/macros.selinux-policy — the file defining
# %%selinux_requires/%%selinux_modules_install/%%selinux_relabel_post,
# all three used below. Fedora's own default mock buildroot happens to
# already carry selinux-policy, so %%selinux_requires "worked" there
# without ever being an explicit BuildRequires of this spec's own —
# EPEL/RHEL's minimal buildroot does not carry it by default, and a
# real `copr-cli build ... --chroot epel-9-x86_64` reproduced the
# resulting failure directly: `error: line 41: Unknown tag:
# %%selinux_requires` — rpm's spec parser, hitting an unrecognized
# macro name outside %%build, tries to read it as a literal `Tag:`
# line and fails, before a single line of %%build ever runs.
#
# Listing both packages here is necessary but, confirmed by testing,
# NOT sufficient by itself on EPEL/RHEL: this exact addition was tried
# alone first and reproduced the identical "Unknown tag" failure again
# — rpm parses this spec's header top-to-bottom in one pass, so by the
# time it reaches line ~68's bare `%%selinux_requires` call, nothing
# has yet acted on the `BuildRequires: selinux-policy` line just above
# it (BuildRequires only affects what mock installs *before* handing
# the chroot to rpmbuild, not what's already available to rpmbuild's
# own header-parsing pass moments later inside it) — a real chicken-
# and-egg case where the macro invocation that would tell mock to
# install selinux-policy itself cannot be parsed without selinux-policy
# already being installed. The fix that actually worked (confirmed by
# a real rebuild against `s0aptile/fossh`'s `epel-9-x86_64`/
# `epel-10-x86_64` chroots, "Unknown tag" gone) was Copr-side, not
# spec-side: `copr-cli edit-chroot s0aptile/fossh/<chroot> --packages
# "selinux-policy selinux-policy-devel"`, which seeds those chroots'
# own baseline buildroot — installed before *any* spec parsing, spec-
# BuildRequires-independent — see docs/PACKAGING-copr.md. These two
# explicit BuildRequires lines are kept anyway: harmless on Fedora
# (already redundant with what's in its default buildroot), and they
# still document the real dependency for anyone building this spec
# outside Copr's own chroot-seeding mechanism (a bare local `mock -r
# epel-9-x86_64`, for instance, has no equivalent of Copr's
# `additional_packages` and would need this project's own
# `%%selinux_requires` call replaced with the literal expansion, or
# its own buildroot pre-seeded some other way, to build at all).
#
# This module is base-package territory, not watchdog: packaging/
# selinux/fossh.te confines `fossh_cgi_t`/`fossh_fcgi_t` only — the
# domains for fossh-cgi and fossh-fcgi, both base-package binaries.
# There is no `fossh_watchdog_t` (that file's own header comment notes
# it as a tracked, separate gap) — so the SELinux toolchain stays an
# unconditional BuildRequires here, not gated to Fedora, and (per
# docs/PACKAGING-copr.md's own confirmation) checkpolicy/
# policycoreutils/selinux-policy all resolve cleanly on EPEL 9/10 too.
BuildRequires:  selinux-policy
BuildRequires:  selinux-policy-devel
%selinux_requires
# gnupg2 is a base-package build *and* run dependency, not just a
# watchdog one: fossh-agent's own operator_auth_client.rs shells out to
# real `gpg` both at runtime (the Wizard screen's key
# generation/export/signing, gated on a live watchdog to actually
# enroll against, but the code itself ships in this package) and in
# its own `#[cfg(test)]` suite (`cargo test --workspace` in %%check
# below genuinely round-trips real `gpg --quick-generate-key`/
# `--export`/`--verify` calls — confirmed by reading those tests, not
# assumed from the crate's name). Fedora's watchdog also shells out to
# gpg/gpgv for its own manifest signing (§3.3) — a second, independent
# reason this package needs it, not a duplicate one.
BuildRequires:  gnupg2
# cmake/clang-devel: BoringSSL's own build (cmake) and bindgen (clang)
# requirements, needed here for a base-package reason, not a watchdog
# one — scripts/build-release.sh unconditionally builds with
# `--features fossh-fcgi/quic,fossh-agent/quic`, and that feature pulls
# in fossh-ipc -> the `quiche` crate -> `boring-sys`, which vendors and
# compiles its own copy of BoringSSL via cmake. This is a *separate*,
# independent BoringSSL build from the one the watchdog subpackage's
# own `scripts/build-quiche-ffi.sh` does for the OCaml ctypes side
# below (see build-release.sh's own header comment, "BoringSSL's
# *other*, independent build path" — that's this one). Both binaries
# built with the quic feature end up statically linking their own copy
# of quiche/BoringSSL (confirmed: no libquiche.so.0 install step exists
# for fossh-fcgi/fossh-agent anywhere in %%install, unlike fossh-watchdog
# below, which needs the dynamic library specifically because ctypes
# resolves symbols with dlsym at runtime — see that script's own header
# comment) — so cmake/clang-devel are needed here, unconditionally, on
# every chroot including EPEL, where both packages resolve fine.
BuildRequires:  cmake
BuildRequires:  clang-devel

Requires:       fcgiwrap
Requires:       gnupg2
Requires:       openssl-libs
Requires(pre):  shadow-utils
%{?systemd_requires}

# Fedora's Users-and-Groups packaging guideline: a package that creates
# its own system accounts via a plain %%pre useradd (rather than the
# newer sysusers.d-macro path) must declare Provides: user()/group()
# for each one, or rpm's own auto-generated Requires: user(fossh-svc)
# group(fossh-svc) (from the %%attr(0700,fossh-svc,fossh-svc) %%files
# entries below) has nothing satisfying it — a real dependency-
# resolution failure ("nothing provides user(fossh-svc)") only a real
# `dnf install` surfaces, never `rpmbuild --nodeps` alone. Found by
# this project's first real clean-VM install verification.
Provides:       user(fossh-svc)
Provides:       group(fossh-svc)

%description
foSSH is a privacy-preserving, embeddable telemetry service:
k-anonymity and rotating-salt visitor hashing instead of raw visitor
identifiers, no third-party data path, self-hosted. This package
provides the portable core, buildable and installable on Fedora and
on RHEL-family systems via EPEL (RHEL, Rocky, Alma; see
docs/PACKAGING-copr.md): two ingest transports (fossh-cgi, a fresh
process per request via fcgiwrap; fossh-fcgi, a persistent FastCGI
process writing to SQLite directly), the fossh CLI, the fossh-agent
local admin console (telemetry dashboard, standalone against the
SQLite store — no watchdog required), hardened systemd units, and an
SELinux policy module confining fossh-cgi and fossh-fcgi.

On Fedora, install fossh-watchdog (a separate subpackage, not
available on EPEL/RHEL) for supervised restart-on-crash, gpg-signed
tamper detection, and the operator-auth enrollment gate fossh-agent's
Wizard screen drives. Without it, fossh-fcgi runs as a plain,
unsupervised systemd service and fossh-agent's Dashboard/Wizard/
OperatorAuth screens report an honest "watchdog unreachable" rather
than doing anything — see this package's own doc, and
docs/PACKAGING-copr.md's "EPEL/RHEL-family build status", for exactly
what that trade-off means.

This is an open-alpha release (%{srcversion}). See
/usr/share/doc/%{name}/README.md.

%if 0%{?fedora}
%package watchdog
Summary:        Supervised, tamper-detected watchdog for fossh-fcgi (Fedora only)
Requires:       %{name} = %{version}-%{release}
Requires:       gnupg2
Requires:       util-linux
Requires(pre):  shadow-utils
%{?systemd_requires}

BuildRequires:  ocaml
BuildRequires:  ocaml-dune
BuildRequires:  ocaml-ctypes-devel
BuildRequires:  ocaml-findlib
BuildRequires:  jq
BuildRequires:  libffi-devel

Provides:       user(fossh-watchdog)
Provides:       group(fossh-watchdog)

%description watchdog
The OCaml watchdog (§3.3): supervises fossh-fcgi (restart on crash),
verifies a gpg-signed tamper-detection manifest before every spawn
(§3.6), and serves both the §3.4 QUIC/mTLS command channel (fossh-agent's
Dashboard screen is a client of it) and the §2.1 human-operator
enrollment/auth gate (fossh-agent's Wizard and OperatorAuth screens
drive it). Owns its own runtime state (`%{_sharedstatedir}/fossh-
watchdog`, `%{_sysconfdir}/fossh`'s setup-token) under a dedicated
`fossh-watchdog` system account, separate from the base package's own
`fossh-svc` (§2.3 privilege separation — the watchdog and the process
it supervises must never share an account).

Fedora only — needs ocaml-ctypes-devel, which is not packaged for
EPEL/RHEL as of this writing (confirmed via a real Copr build against
`epel-9-x86_64`/`epel-10-x86_64`; see docs/PACKAGING-copr.md's
"EPEL/RHEL-family build status" for the full investigation). Requires
the base %{name} package (exact version match) — this subpackage ships
no ingest transport of its own; it supervises the one the base package
already installs.
%endif

%package console
Summary:        Desktop console for administering a foSSH install
Requires:       %{name} = %{version}-%{release}
# The console is a pure-Python GTK4 application. It is `noarch` in
# spirit but not in fact: it Requires the base package, which is not,
# and splitting it further to gain that would mean two source packages
# for one product.
BuildArch:      noarch
Requires:       python3 >= 3.9
Requires:       python3-gobject
Requires:       gtk4 >= 4.10
Requires:       libadwaita >= 1.4
# The only outbound request foSSH ever makes is an operator-triggered
# integration test, and this is what makes it. See ADR-0063 for why a
# system tool rather than an HTTP crate.
Requires:       curl
# Recommends, not Requires: the console detects at runtime what is
# actually installed and falls back to the theme's own fonts and
# symbolic icons. It looks as designed with these and works without
# them, which is the right strength for a dependency that is purely
# presentational.
Recommends:     google-roboto-fonts
Recommends:     google-roboto-mono-fonts
Recommends:     material-icons-fonts
# Integration verification drives a real browser. Playwright is not
# packaged by Fedora and its Chromium is a large download, so this is
# a suggestion rather than a dependency: the console checks at runtime
# and simply does not offer the check when it cannot run it.
Suggests:       python3-playwright
BuildRequires:  python3-devel
BuildRequires:  desktop-file-utils
BuildRequires:  libappstream-glib
BuildRequires:  appstream

%description console
foSSH Console is the local administration interface for a foSSH
install: today's figures across every site, real k-anonymised queries
against the rollup store, management of external services added with an
API key, and the first-run operator enrollment flow.

It never listens on a socket. Everything it shows comes from
fossh-agent, a helper process it spawns over a pipe, and no credential
outlives the call that carries it.

This package replaces the fossh-tui terminal console shipped up to
0.1.3, which is retired along with the rest of that line — see
RETIREMENT.md.


%package selfheal
Summary:        Optional local-model advisory layer for foSSH self-healing
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}
Requires:       httpd
Requires:       gnupg2
# Deliberately NOT `Requires: ollama`: Ollama is not packaged for
# Fedora or EPEL, so naming it would make this subpackage
# uninstallable from any repository it is shipped in. The endpoint is
# probed at runtime and its absence is an ordinary, reported state —
# see %%description.
Suggests:       vulkan-loader

%description selfheal
foSSH's self-healing runs deterministic rules over the real state of an
install and reports what it finds, with a remedy for each. That part is
in the base package, always runs, and is the whole feature.

This subpackage adds an OPTIONAL local language model
(lfm2.5-thinking:1.2b, served by Ollama) that may write one thing: a
plain-language explanation attached to a finding the rules already
produced. It cannot create a finding, change a severity, alter a
remedy, or cause anything to be executed. Installing or removing it
changes nothing about what foSSH diagnoses or repairs.

It runs only where it can do so without competing with the work the
machine is actually for: AVX2 is required and AVX-512 preferred, Vulkan
is a fallback for machines without AVX2, and the floor is six physical
cores with 8 GiB of RAM — an AMD Ryzen 5 2600 or Intel Core i5-8400 and
upward. Hardware that passes is then timed against a real generation,
and anything below the throughput floor switches the layer off for that
session rather than slowing the server down.

Ollama itself is not packaged by Fedora and is not pulled in by this
subpackage. Without it, the endpoint is simply unreachable and
self-healing reports that plainly while continuing to work.

This package installs an Apache configuration that puts the model
endpoint behind a per-install secret on loopback. Ollama's own bind
address keeps the network out; it does not keep other local accounts
out, which is what this adds.



%prep
%autosetup -n %{name}-%{srcversion}

%build
# No `--offline`/vendored-dependency setup yet (tracked under §3.10
# supply-chain hardening, not done as of this spec) — a real Koji/mock
# build, which blocks network access, needs `cargo vendor` plus a
# `.cargo/config.toml` pointing at it bundled into the source tarball
# first. This works today only because the build environment's cargo
# registry cache is already warm.
#
# scripts/build-release.sh (not a bare `cargo build --release`) sets
# --remap-path-prefix so panic-location strings baked into the
# binaries don't embed this build host's absolute paths — §19.4.12's
# identity-hygiene gate, verified with `strings` after the build. It
# always builds the base package's own binaries with the quic feature
# on (see that script's own header comment) — the QUIC client code
# ships in this package's fossh-fcgi/fossh-agent on every chroot,
# Fedora or EPEL, even though it has nothing to dial into without the
# (Fedora-only) watchdog subpackage also installed; it fails soft in
# that case, the same documented posture as everywhere else in this
# project's own quic-off code paths.
./scripts/build-release.sh
checkmodule -m -o packaging/selinux/fossh.mod packaging/selinux/fossh.te
semodule_package -o packaging/selinux/fossh.pp -m packaging/selinux/fossh.mod -f packaging/selinux/fossh.fc

%if 0%{?fedora}
# Deliberately NOT `eval $(opam env)` or anything opam-related — dune
# resolves ocaml/ocaml-dune/ocaml-ctypes from the system findlib
# database installed by the BuildRequires above, the same real,
# clean-env build path §3.3's own logic layer already used before
# §3.4's ctypes bindings existed.
#
# watchdog/quic/'s own dune file links against
# watchdog/quic/vendor/libquiche.so, which does not exist until this
# runs — quiche is never an ordinary Cargo dependency of anything
# built above (see scripts/build-quiche-ffi.sh's own header comment),
# so nothing earlier in this %%build already produced it.
./scripts/build-quiche-ffi.sh
(cd watchdog && dune build --profile release)
%endif

%check
# Dev-profile, not %%build's release profile — a second, separate
# build/test cycle, same as every other test run in this project (see
# dev/DURUM.md). Same network caveat as %%build above: needs a warm
# cargo registry cache, not yet safe under a network-denied mock/koji
# build (§3.10). Runs on every chroot, EPEL included — real `gpg` is
# already a BuildRequires above for exactly this (fossh-agent's own
# operator_auth_client.rs tests round-trip it); the one OCaml interop
# test in this suite (fossh-admin's bootstrap_interop.rs) skips itself,
# rather than failing, when it doesn't find a compiled watchdog binary
# in this checkout — the documented behavior for "the OCaml side
# wasn't built here", which on EPEL it never is.
cargo test --workspace
(cd crates/fossh-ffi && cargo test)

%if 0%{?fedora}
# LD_LIBRARY_PATH: every test binary this produces links against
# libquiche.so.0 now (test/dune's single `(tests ...)` stanza puts all
# of them in one executables group sharing fossh_watchdog_quic as a
# dependency, not just test_quic.exe), and %%post's `ldconfig` hasn't
# run yet at this point in a package build — there is no other way for
# the dynamic linker to find a library that lives in this source tree,
# not yet in any system library path.
(cd watchdog && LD_LIBRARY_PATH="$(pwd)/quic/vendor" dune test)
%endif

%install
install -D -m0755 target/release/fossh %{buildroot}%{_bindir}/fossh
install -D -m0755 target/release/fossh-cgi %{buildroot}%{_bindir}/fossh-cgi
install -D -m0755 target/release/fossh-fcgi %{buildroot}%{_bindir}/fossh-fcgi
# %%{_libexecdir}, not %%{_bindir}: fossh-agent is a helper the console
# spawns over a pipe, not a command anyone runs by hand. Putting it on
# PATH would invite exactly that, and its stdout is a protocol stream
# that is useless in a terminal.
install -D -m0755 target/release/fossh-agent %{buildroot}%{_libexecdir}/%{name}/fossh-agent

# Explicit, not relied-upon-implicitly: Cargo's own `strip = true`
# strips these before they're even copied in here, but rpm's automatic
# post-install stripping is tied to automatic debuginfo generation
# (%%global debug_package %%{nil}, above) on this rpm version, and
# turning that off turned off the automatic strip too — observed
# directly (`file` reported "not stripped" on a build with automatic
# debuginfo disabled, on binaries `cargo build` itself had *just*
# stripped moments before `install -D` copied them in), not assumed.
strip --strip-all %{buildroot}%{_bindir}/fossh %{buildroot}%{_bindir}/fossh-cgi %{buildroot}%{_bindir}/fossh-fcgi %{buildroot}%{_libexecdir}/%{name}/fossh-agent

install -D -m0644 packaging/systemd/fossh-fcgiwrap.socket %{buildroot}%{_unitdir}/fossh-fcgiwrap.socket
install -D -m0644 packaging/systemd/fossh-fcgiwrap.service %{buildroot}%{_unitdir}/fossh-fcgiwrap.service
install -D -m0644 packaging/systemd/fossh-fcgi.service %{buildroot}%{_unitdir}/fossh-fcgi.service
install -D -m0644 packaging/systemd/fossh.tmpfiles.conf %{buildroot}%{_tmpfilesdir}/fossh.conf

install -D -m0644 packaging/selinux/fossh.pp %{buildroot}%{_datadir}/selinux/packages/fossh/fossh.pp

install -d -m0700 %{buildroot}%{_sharedstatedir}/fossh

%if 0%{?fedora}
install -D -m0755 watchdog/_build/default/bin/main.exe %{buildroot}%{_bindir}/fossh-watchdog

# fossh-watchdog's DT_NEEDED dependency on libquiche.so.0 (§3.4) —
# quiche is not a Fedora-packaged system library, so there is nothing
# to add to Requires: for it; this subpackage carries its own copy,
# installed to a package-private directory (not %%{_libdir} directly,
# so it can never shadow or collide with some *other* package's own
# unrelated libquiche build) and made discoverable via an
# ld.so.conf.d drop-in + `ldconfig` in %%post/%%postun below, the
# standard Fedora pattern for a private shared library exactly one
# package's own binaries use. Installed *before* the strip line below,
# not after: `strip` on a path that doesn't exist yet fails the whole
# %%install step outright, under `set -e`.
install -D -m0755 watchdog/quic/vendor/libquiche.so %{buildroot}%{_libdir}/fossh/libquiche.so.0
install -d -m0755 %{buildroot}%{_sysconfdir}/ld.so.conf.d
echo "%{_libdir}/fossh" > %{buildroot}%{_sysconfdir}/ld.so.conf.d/fossh-libquiche.conf

strip --strip-all %{buildroot}%{_bindir}/fossh-watchdog %{buildroot}%{_libdir}/fossh/libquiche.so.0

install -D -m0644 packaging/systemd/fossh-watchdog.service %{buildroot}%{_unitdir}/fossh-watchdog.service

install -d -m0700 %{buildroot}%{_sharedstatedir}/fossh-watchdog
# §2.6's setup-token file (Setup_token.ensure) lives at
# %{_sysconfdir}/fossh/setup-token — persistent, not /run, so this
# follows the same install-d-then-chown-in-%%post shape as
# %{_sharedstatedir}/fossh-watchdog above rather than fossh.tmpfiles.conf
# (that file's own header comment explains why it's reserved for /run:
# a tmpfs wiped every reboot, which /etc is not). Owned by the watchdog
# subpackage entirely — the watchdog is the only thing that ever writes
# this token (Setup_token.ensure's own `Unix.mkdir` recovery path is
# belt-and-suspenders, not the only thing standing between a fresh
# install and a working setup flow); on a base-only (EPEL) install
# nothing ever creates or populates it, and fossh-agent's Wizard screen
# reports an honest "no setup token" rather than assuming one exists.
install -d -m0700 %{buildroot}%{_sysconfdir}/fossh
%endif

# --- fossh-console (GTK4/libadwaita, Python) ---
#
# Installed into the interpreter's own site-packages rather than a
# private directory plus a PYTHONPATH wrapper: the latter breaks the
# moment anyone runs a module directly, and Fedora's Python packaging
# guidelines are explicit that an importable package belongs on the
# real path.
install -d -m0755 %{buildroot}%{python3_sitelib}/fossh_console
install -d -m0755 %{buildroot}%{python3_sitelib}/fossh_console/views
install -m0644 gui/fossh_console/*.py %{buildroot}%{python3_sitelib}/fossh_console/
install -m0644 gui/fossh_console/style.css %{buildroot}%{python3_sitelib}/fossh_console/
install -m0644 gui/fossh_console/views/*.py %{buildroot}%{python3_sitelib}/fossh_console/views/

install -D -m0755 gui/fossh-console %{buildroot}%{_bindir}/fossh-console

# Provider templates: shipped definitions in %%{_datadir}, plus the
# empty drop-in directory an administrator adds their own to. The
# directory is created here so it exists to be found rather than
# having to be invented from documentation.
install -d -m0755 %{buildroot}%{_datadir}/%{name}/providers
install -m0644 packaging/providers/*.toml %{buildroot}%{_datadir}/%{name}/providers/
install -d -m0755 %{buildroot}%{_sysconfdir}/%{name}/providers.d

install -D -m0644 docs/man/fossh-console.1 \
    %{buildroot}%{_mandir}/man1/fossh-console.1

install -D -m0644 gui/data/org.fossh.Console.desktop \
    %{buildroot}%dir %{_datadir}/%{name}
%dir %{_datadir}/%{name}/providers
%{_datadir}/%{name}/providers/*.toml
%dir %{_sysconfdir}/%{name}/providers.d
%{_datadir}/applications/org.fossh.Console.desktop
install -D -m0644 gui/data/org.fossh.Console.metainfo.xml \
    %{buildroot}%{_metainfodir}/org.fossh.Console.metainfo.xml
install -D -m0644 gui/data/icons/org.fossh.Console.svg \
    %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/org.fossh.Console.svg
install -D -m0644 gui/data/icons/org.fossh.Console-symbolic.svg \
    %{buildroot}%{_datadir}/icons/hicolor/symbolic/apps/org.fossh.Console-symbolic.svg

# Both validators are BuildRequires of the console subpackage and both
# fail the build rather than warning. A .desktop file with a bad key
# or a metainfo file AppStream cannot parse installs perfectly happily
# and then simply does not appear in anyone's software centre, which
# is the kind of defect that is only ever found by a user.
desktop-file-validate %{buildroot}%dir %{_datadir}/%{name}
%dir %{_datadir}/%{name}/providers
%{_datadir}/%{name}/providers/*.toml
%dir %{_sysconfdir}/%{name}/providers.d
%{_datadir}/applications/org.fossh.Console.desktop
appstream-util validate-relax --nonet \
    %{buildroot}%{_metainfodir}/org.fossh.Console.metainfo.xml
# appstreamcli is the stricter of the two and the one whose rules the
# software centres themselves follow. Both are run because they
# disagree about what matters: appstream-util caught nothing here that
# appstreamcli did not, but the reverse has not been true historically.
appstreamcli validate --no-net \
    %{buildroot}%{_metainfodir}/org.fossh.Console.metainfo.xml

# --- fossh-selfheal (optional local-model advisory layer) ---
install -D -m0644 packaging/apache/fossh-model.conf \
    %{buildroot}%{_sysconfdir}/httpd/conf.d/fossh-model.conf
install -D -m0644 packaging/model/Modelfile \
    %{buildroot}%{_datadir}/%{name}/model/Modelfile


%pre
# §2.3: purpose-created system user for the base package's own ingest
# processes (fossh-cgi/fossh-fcgi) — kept separate from the watchdog's
# own account (%%pre watchdog below) so "watchdog supervises core" is a
# real security boundary, not just process management, on installs
# that have both.
getent group fossh-svc >/dev/null || groupadd -r fossh-svc
getent passwd fossh-svc >/dev/null || useradd -r -g fossh-svc -d %{_sharedstatedir}/fossh -s /sbin/nologin -c "foSSH ingest service" fossh-svc
exit 0

%if 0%{?fedora}
%pre watchdog
getent group fossh-watchdog >/dev/null || groupadd -r fossh-watchdog
getent passwd fossh-watchdog >/dev/null || useradd -r -g fossh-watchdog -d %{_sharedstatedir}/fossh-watchdog -s /sbin/nologin -c "foSSH watchdog" fossh-watchdog
exit 0
%endif

%post
# /run/fossh{,/salt} (packaging/systemd/fossh.tmpfiles.conf) are
# tmpfiles.d entries — normally only materialized by
# systemd-tmpfiles-setup.service at boot. Without this, `dnf install`
# on an already-running system leaves them missing until the next
# reboot; a setup wizard or manual service start in between would find
# the salt directory absent. rpmlint's `post-without-tmpfile-creation`
# caught this — a real gap, not noise.
systemd-tmpfiles --create %{_tmpfilesdir}/fossh.conf
%selinux_modules_install -p 200 %{_datadir}/selinux/packages/fossh/fossh.pp
chown fossh-svc:fossh-svc %{_sharedstatedir}/fossh
restorecon -R %{_bindir}/fossh-cgi %{_bindir}/fossh-fcgi %{_sharedstatedir}/fossh >/dev/null 2>&1 || :
%systemd_post fossh-fcgiwrap.socket
# dnf install fossh leaves fossh-fcgiwrap.socket enabled but not
# started, and fossh-fcgi.service (below) not even enabled — see the
# next paragraph. On a base-only (EPEL) install there is no operator
# auth gate to wait on at all; an admin who wants fossh-fcgi running
# unsupervised enables fossh-fcgi.service themselves.
#
# Deliberately NOT %%systemd_post'd here: fossh-fcgi.service. It's a
# real, supported alternative transport (persistent FastCGI,
# unsupervised, §7.2) an admin can still `systemctl enable` explicitly
# — but on a Fedora install with the watchdog subpackage also present,
# it must never both preset-enable alongside fossh-watchdog.service,
# which execs fossh-fcgi itself (see that unit's own header comment)
# and would otherwise fight it over FOSSH_FCGI_SOCKET. A real clean-VM
# run of this exact %%post caught this live, not by inspection:
# `%%systemd_post fossh-fcgi.service` used to sit right here — dropped
# for that reason, and the same reasoning applies unchanged now that
# fossh-watchdog.service lives in a separate subpackage.

%if 0%{?fedora}
%post watchdog
# Must run before anything below might exec fossh-watchdog (nothing in
# this %%post does yet, but a future setup-wizard-triggered start
# could) — the freshly-installed libquiche.so.0 and its
# ld.so.conf.d/fossh-libquiche.conf entry only take effect once
# ldconfig has rebuilt the dynamic linker's cache.
/sbin/ldconfig
chown fossh-watchdog:fossh-watchdog %{_sharedstatedir}/fossh-watchdog
chown fossh-watchdog:fossh-watchdog %{_sysconfdir}/fossh
restorecon -R %{_bindir}/fossh-watchdog %{_sharedstatedir}/fossh-watchdog %{_sysconfdir}/fossh >/dev/null 2>&1 || :
runuser -u fossh-watchdog -- %{_bindir}/fossh-watchdog generate-manifest \
  %{_sharedstatedir}/fossh-watchdog/gnupghome \
  %{_sharedstatedir}/fossh-watchdog/manifest.asc \
  %{_bindir}/fossh-fcgi \
  || :
%systemd_post fossh-watchdog.service
# fossh-watchdog.service is left enabled but not started, same reason
# as fossh-fcgiwrap.socket in the base package's own %%post: the §2.1
# operator auth gate has no enrolled key yet, so nothing should answer
# application requests until the setup wizard (fossh-agent) completes.
%endif

%post selfheal
# The secret Apache checks against, generated once, as root, with
# ownership neither side could have arranged for itself: Apache runs
# as `apache` and the agent as `fossh-svc`, so a file readable by only
# one of them makes the endpoint either unreachable or unguarded.
#
# `printf`, never `echo`: a trailing newline here silently breaks the
# comparison in fossh-model.conf forever. See that file's own comment.
if [ ! -s %{_sysconfdir}/fossh/model-access-secret ]; then
    install -d -m0755 %{_sysconfdir}/fossh
    umask 077
    printf '%%s' "$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')" \
        > %{_sysconfdir}/fossh/model-access-secret
    chgrp apache %{_sysconfdir}/fossh/model-access-secret 2>/dev/null || :
    chmod 0640 %{_sysconfdir}/fossh/model-access-secret
fi
# So the agent can read the same file Apache does.
usermod -a -G apache fossh-svc >/dev/null 2>&1 || :

%preun
%systemd_preun fossh-fcgiwrap.socket fossh-fcgiwrap.service
%systemd_preun fossh-fcgi.service

%if 0%{?fedora}
%preun watchdog
%systemd_preun fossh-watchdog.service
%endif

%postun
%systemd_postun_with_restart fossh-fcgiwrap.socket
%systemd_postun_with_restart fossh-fcgi.service
if [ $1 -eq 0 ]; then
  %selinux_modules_uninstall -p 200 fossh
fi

%if 0%{?fedora}
%postun watchdog
/sbin/ldconfig
%systemd_postun_with_restart fossh-watchdog.service
%endif

%posttrans
%selinux_relabel_post

%files
%license LICENSE
%doc README.md
%{_bindir}/fossh
%{_bindir}/fossh-cgi
%{_bindir}/fossh-fcgi
%dir %{_libexecdir}/%{name}
%{_libexecdir}/%{name}/fossh-agent
%{_unitdir}/fossh-fcgiwrap.socket
%{_unitdir}/fossh-fcgiwrap.service
%{_unitdir}/fossh-fcgi.service
%{_tmpfilesdir}/fossh.conf
%{_datadir}/selinux/packages/fossh/fossh.pp
%attr(0700,fossh-svc,fossh-svc) %dir %{_sharedstatedir}/fossh

%if 0%{?fedora}
%files watchdog
%{_bindir}/fossh-watchdog
%dir %{_libdir}/fossh
%{_libdir}/fossh/libquiche.so.0
%{_sysconfdir}/ld.so.conf.d/fossh-libquiche.conf
%{_unitdir}/fossh-watchdog.service
%attr(0700,fossh-watchdog,fossh-watchdog) %dir %{_sharedstatedir}/fossh-watchdog
%attr(0700,fossh-watchdog,fossh-watchdog) %dir %{_sysconfdir}/fossh
%endif

%files console
%license LICENSE
# Read at runtime by the console's Legal page, not merely shipped as
# documentation: an operator who installed from a software centre has
# no source tree, and "see tos.md" is not an answer to them.
%doc RETIREMENT.md
%doc tos.md
%doc PRIVACY.md
%{_bindir}/fossh-console
%{_mandir}/man1/fossh-console.1*
%{python3_sitelib}/fossh_console/
%dir %{_datadir}/%{name}
%dir %{_datadir}/%{name}/providers
%{_datadir}/%{name}/providers/*.toml
%dir %{_sysconfdir}/%{name}/providers.d
%{_datadir}/applications/org.fossh.Console.desktop
%{_metainfodir}/org.fossh.Console.metainfo.xml
%{_datadir}/icons/hicolor/scalable/apps/org.fossh.Console.svg
%{_datadir}/icons/hicolor/symbolic/apps/org.fossh.Console-symbolic.svg

%files selfheal
%license LICENSE
%doc docs/SELF-HEALING.md
# %%config(noreplace): an operator who has edited the vhost -- a
# different port, an extra Require -- must not have it silently
# replaced on upgrade. rpm leaves theirs and writes ours alongside as
# .rpmnew.
%config(noreplace) %{_sysconfdir}/httpd/conf.d/fossh-model.conf
# %%{_datadir}/fossh itself is owned by fossh-console, which is not a
# dependency of this subpackage -- so it is claimed here too. Shared
# ownership of a directory is legal in rpm and is the correct fix;
# leaving it unowned is what produces an orphaned directory after an
# uninstall.
%dir %{_datadir}/%{name}
%dir %{_datadir}/%{name}/model
%{_datadir}/%{name}/model/Modelfile


%changelog
* Sat Aug 15 2026 s0aptile <noreply@example.invalid> - 0.2.0~alpha.1-1
- Retire the whole 0.1.x line. See RETIREMENT.md for what was actually
  broken in it, rather than a general "superseded" note.
- Replace the fossh-tui terminal console with two things: fossh-agent,
  a headless JSON-lines helper now installed to %%{_libexecdir}/fossh
  rather than onto PATH (its stdout is a protocol stream, not output),
  and a new fossh-console subpackage -- a GTK4/libadwaita desktop
  application, with .desktop entry, AppStream metainfo and icons, both
  validated during the build rather than at install time.
- New fossh-selfheal subpackage: the optional, capability-gated local
  model advisory layer, plus the Apache configuration that keeps its
  endpoint closed to other local accounts. The deterministic
  self-healing rules are in the base package and are unaffected by
  whether this is installed.
- Both new subpackages build on EPEL/RHEL as well as Fedora; only
  fossh-watchdog remains Fedora-only, for the reason it always was
  (ocaml-ctypes-devel is not in EPEL).

* Fri Aug 07 2026 s0aptile <noreply@example.invalid> - 0.2.0~alpha.1-2
- Split into a portable base package (fossh: fossh-cgi, fossh-fcgi,
  fossh-agent, fossh CLI, SELinux policy confining fossh-cgi/fossh-fcgi
  — all pure Rust, buildable on EPEL/RHEL 9/10 too) and a Fedora-only
  fossh-watchdog subpackage (the OCaml watchdog, needs
  ocaml-ctypes-devel, confirmed absent from EPEL 9/10). Fixes the
  EPEL/RHEL Copr build, previously blocked outright by that missing
  dependency — see docs/PACKAGING-copr.md's "EPEL/RHEL-family build
  status" for the real, confirmed Copr build result on both new
  chroots. No change to the Fedora-native package's own installed
  contents (base + watchdog together match the prior single-package
  %%files exactly).

* Thu Aug 06 2026 s0aptile <noreply@example.invalid> - 0.2.0~alpha.1-1
- §2.1 human-operator auth gate finished end to end: watchdog-side
  listener, real §2.6 setup-token flow gating enrollment, and the
  Rust/TUI client, all adversarially reviewed with real findings fixed
  (a process-killing SIGPIPE gap, an O(n^2) DoS, a thread-collision
  race, among others).
- fossh-watchdog.service added; TUI live-query wiring for watchdog and
  tamper-detection status.
- First real clean-VM install verification this project has ever run,
  surfacing and fixing 3 real packaging bugs invisible to
  rpmbuild --nodeps alone (missing Provides: user()/group(), unexpanded
  SELinux gen_context() macros, an untracked-files gap in the release
  tarball snapshot).
- Long fuzz pass (933.9M executions across 5 targets, zero crashes),
  supply-chain/identity-hygiene re-audit, and a second independent
  identity leak found and fixed (BoringSSL's own build path via
  fossh-agent's quic feature).
  Still 0.1.x/open-alpha — no interface-breaking changes.

* Tue Aug 04 2026 s0aptile <noreply@example.invalid> - 0.1.2~alpha.1-1
- Open alpha refinement: TUI dark-graphite theme completed, stale
  status text in the local admin console and dev docs corrected.
  Still 0.1.x/open-alpha — no interface-breaking changes.
  (0.1.1 was never built or shipped — this supersedes it directly.)

* Sun Aug 02 2026 s0aptile <noreply@example.invalid> - 0.1.0~alpha.1-1
- Open alpha.
