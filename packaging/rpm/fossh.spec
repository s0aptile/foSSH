# foSSH RPM spec (chapter §3.11). No `rust2rpm`/Fedora Rust-packaging
# macros used — this build environment doesn't have that package, so
# %%build/%%install are plain `cargo build --release --workspace` plus
# manual `install -D`, which is a valid, common alternative to the full
# Fedora Rust packaging guideline flow, just less automated.
#
# Version note: `%%{srcversion}` (hyphenated, matches Cargo's own
# `0.1.0-alpha.1`) names the source tarball/directory; `%%{version}`
# (tilde form, RPM's own prerelease convention — sorts *before*
# `0.1.0` with no suffix, which is the ordering an alpha needs) is what
# actually appears in the built package's metadata. Kept separate so
# neither has to deal with the other's separator character.
%global srcversion 0.1.0-alpha.1
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
Version:        0.1.0~alpha.1
Release:        1%{?dist}
Summary:        Privacy-preserving, embeddable telemetry (self-hosted analytics)

License:        MIT
URL:            https://github.com/s0aptile/foSSH
Source0:        %{name}-%{srcversion}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  gcc
BuildRequires:  checkpolicy
BuildRequires:  policycoreutils
BuildRequires:  systemd-rpm-macros
%selinux_requires

Requires:       fcgiwrap
Requires(pre):  shadow-utils
%{?systemd_requires}

%description
foSSH is a privacy-preserving, embeddable telemetry service:
k-anonymity and rotating-salt visitor hashing instead of raw visitor
identifiers, no third-party data path, self-hosted. This package
provides the Fedora-native deployment: two ingest transports
(fossh-cgi, a fresh process per request via fcgiwrap; fossh-fcgi, a
persistent FastCGI process writing to SQLite directly), the fossh CLI,
the fossh-tui local admin console and first-run setup wizard, hardened
systemd units, and an SELinux policy module (currently covering
fossh-cgi only — see fossh-fcgi.service's own header comment).

This is an open-alpha release (%{srcversion}). See
/usr/share/doc/%{name}/README.md.

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
# identity-hygiene gate, verified with `strings` after the build.
./scripts/build-release.sh
checkmodule -m -o packaging/selinux/fossh.mod packaging/selinux/fossh.te
semodule_package -o packaging/selinux/fossh.pp -m packaging/selinux/fossh.mod -f packaging/selinux/fossh.fc

%check
# Dev-profile, not %%build's release profile — a second, separate
# build/test cycle, same as every other test run in this project (see
# dev/DURUM.md). Same network caveat as %%build above: needs a warm
# cargo registry cache, not yet safe under a network-denied mock/koji
# build (§3.10).
cargo test --workspace
(cd crates/fossh-ffi && cargo test)

%install
install -D -m0755 target/release/fossh %{buildroot}%{_bindir}/fossh
install -D -m0755 target/release/fossh-cgi %{buildroot}%{_bindir}/fossh-cgi
install -D -m0755 target/release/fossh-fcgi %{buildroot}%{_bindir}/fossh-fcgi
install -D -m0755 target/release/fossh-tui %{buildroot}%{_bindir}/fossh-tui
# Explicit, not relied-upon-implicitly: Cargo's own `strip = true`
# strips these before they're even copied in here, but rpm's automatic
# post-install stripping is tied to automatic debuginfo generation
# (%%global debug_package %%{nil}, above) on this rpm version, and
# turning that off turned off the automatic strip too — observed
# directly (`file` reported "not stripped" on a build with automatic
# debuginfo disabled, on binaries `cargo build` itself had *just*
# stripped moments before `install -D` copied them in), not assumed.
# Stripping explicitly here means the installed binaries stay stripped
# regardless of which rpm macro is or isn't wired to do it implicitly.
strip --strip-all %{buildroot}%{_bindir}/fossh %{buildroot}%{_bindir}/fossh-cgi %{buildroot}%{_bindir}/fossh-fcgi %{buildroot}%{_bindir}/fossh-tui

install -D -m0644 packaging/systemd/fossh-fcgiwrap.socket %{buildroot}%{_unitdir}/fossh-fcgiwrap.socket
install -D -m0644 packaging/systemd/fossh-fcgiwrap.service %{buildroot}%{_unitdir}/fossh-fcgiwrap.service
install -D -m0644 packaging/systemd/fossh-fcgi.service %{buildroot}%{_unitdir}/fossh-fcgi.service
install -D -m0644 packaging/systemd/fossh.tmpfiles.conf %{buildroot}%{_tmpfilesdir}/fossh.conf

install -D -m0644 packaging/selinux/fossh.pp %{buildroot}%{_datadir}/selinux/packages/fossh/fossh.pp

install -d -m0700 %{buildroot}%{_sharedstatedir}/fossh

%pre
# §2.3: two purpose-created system users, not one — the watchdog
# (chapter §3.3, not yet built) and the core service must never share
# an account, or "watchdog supervises core" is just process
# management, not a security boundary.
getent group fossh-svc >/dev/null || groupadd -r fossh-svc
getent passwd fossh-svc >/dev/null || useradd -r -g fossh-svc -d %{_sharedstatedir}/fossh -s /sbin/nologin -c "foSSH ingest service" fossh-svc
getent group fossh-watchdog >/dev/null || groupadd -r fossh-watchdog
getent passwd fossh-watchdog >/dev/null || useradd -r -g fossh-watchdog -d %{_sharedstatedir}/fossh-watchdog -s /sbin/nologin -c "foSSH watchdog" fossh-watchdog
exit 0

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
%systemd_post fossh-fcgi.service
# dnf install fossh leaves both ingest transports enabled but not
# started — the watchdog's auth gate (chapter §3.3/§2.1, not yet built)
# has no enrolled key yet, and neither should answer application
# requests until the setup wizard (fossh-tui) completes. This package
# does not start either on its own, and does not choose between them:
# fossh-fcgiwrap.socket (CGI, via fcgiwrap) and fossh-fcgi.service
# (persistent FastCGI, §7.2) are two transports for the same pipeline,
# not a default-plus-alternative — enabling both costs nothing since
# neither starts on its own, and the operator picks which to actually
# run once the setup wizard's full flow lands (§3.11).

%preun
%systemd_preun fossh-fcgiwrap.socket fossh-fcgiwrap.service
%systemd_preun fossh-fcgi.service

%postun
%systemd_postun_with_restart fossh-fcgiwrap.socket
%systemd_postun_with_restart fossh-fcgi.service
if [ $1 -eq 0 ]; then
  %selinux_modules_uninstall -p 200 fossh
fi

%posttrans
%selinux_relabel_post

%files
%license LICENSE
%doc README.md
%{_bindir}/fossh
%{_bindir}/fossh-cgi
%{_bindir}/fossh-fcgi
%{_bindir}/fossh-tui
%{_unitdir}/fossh-fcgiwrap.socket
%{_unitdir}/fossh-fcgiwrap.service
%{_unitdir}/fossh-fcgi.service
%{_tmpfilesdir}/fossh.conf
%{_datadir}/selinux/packages/fossh/fossh.pp
%attr(0700,fossh-svc,fossh-svc) %dir %{_sharedstatedir}/fossh

%changelog
* Sun Aug 02 2026 s0aptile <noreply@example.invalid> - 0.1.0~alpha.1-1
- Open alpha.
