#!/bin/sh
# Builds every release binary/library with --remap-path-prefix set, so
# panic-location strings (file!()/line!() baked in even in a stripped
# binary — `strip = true` only removes debug symbols, not these) never
# embed the real build machine's absolute paths. Part of §19.4.12's
# identity-hygiene gate: "No absolute build paths leak into binaries:
# build with --remap-path-prefix, then strings the release artifacts
# and grep for /home/ and /Users/. Zero hits."
#
# The prefixes are computed here, not hardcoded, because the source
# checkout path and the Cargo registry cache path are both specific to
# whichever machine is actually running this build (a contributor's
# home directory, a Koji/mock chroot, ...) — a committed config file
# can't know either of those in advance. Run this instead of a bare
# `cargo build --release`.
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cargo_home="${CARGO_HOME:-$HOME/.cargo}"

export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=${project_root}=/build/fossh --remap-path-prefix=${cargo_home}=/build/cargo-registry"

# §3.8: `fossh-store` links SQLCipher (`libsqlite3-sys`'s
# `bundled-sqlcipher` feature) against the *system* OpenSSL for its
# crypto backend, via a bare `-lcrypto` with no explicit `-L` of its
# own — it relies entirely on the linker's default system search path.
# That's fine on its own, but this script (unlike an ordinary `cargo
# build`) unconditionally enables `quic` below, which pulls in
# `boring-sys` (vendored BoringSSL for `quiche`) into the *same*
# binaries (`fossh-fcgi`, `fossh-agent`) — and BoringSSL's own build
# output is *also* a file literally named `libcrypto.a`, sitting in a
# directory that *is* on the linker's explicit `-L` list (its own
# `OUT_DIR`), unlike the real system OpenSSL. A bare `-lcrypto` then
# resolves against BoringSSL's archive first, which doesn't implement
# the OpenSSL 3.0 `EVP_MAC` family SQLCipher's HMAC backend needs —
# real, reproduced undefined-symbol link errors
# (`EVP_MAC_fetch`/`EVP_MAC_CTX_new`/etc.) in exactly this script's own
# `--features ...quic` build, not in an ordinary scoped `cargo build`
# that never links BoringSSL at all. Letting some symbols resolve from
# BoringSSL and others from real OpenSSL for the same `EVP_CIPHER_CTX`/
# `EVP_MAC_CTX` structs would "fix" the link while leaving a genuine
# ABI-mismatch hazard in a security-relevant code path, so the fix
# hands the linker the *exact* system `libcrypto.so` as a direct file
# argument — sidestepping the `-L` search-order race entirely, so every
# symbol `libsqlite3-sys` needs resolves consistently from the one real
# OpenSSL before BoringSSL's colliding archive is ever reached. See
# DECISIONS.md for the fuller writeup. Discovered via `pkg-config`
# rather than hardcoded, consistent with this script's own "computed
# here, not hardcoded" stance above; a no-op (this script still builds,
# same as before this fix existed) if `pkg-config`/the dev symlink
# aren't present, rather than failing a build that would have worked
# fine without it outside this exact feature combination.
openssl_libdir=$(pkg-config --variable=libdir openssl 2>/dev/null || true)
if [ -n "$openssl_libdir" ] && [ -e "${openssl_libdir}/libcrypto.so" ]; then
    export RUSTFLAGS="${RUSTFLAGS} -C link-arg=${openssl_libdir}/libcrypto.so"
else
    echo "build-release: warning: could not locate libcrypto.so via pkg-config (openssl-devel installed?) — the --features ...quic build below may fail to link fossh-fcgi/fossh-agent against SQLCipher's OpenSSL backend" >&2
fi

# CFLAGS/CXXFLAGS alongside RUSTFLAGS, same reasoning and same fix
# shape as scripts/build-quiche-ffi.sh's own already-applied one:
# --remap-path-prefix only touches rustc. Since this script started
# unconditionally building with --features fossh-fcgi/quic,fossh-agent/quic
# (see the comment further down), `boring-sys`'s own separate,
# independent BoringSSL vendoring (pulled in by `quiche` -> `boring`
# for fossh-agent's/fossh-ipc's cmake-driven C++ build) got exercised by
# an ordinary release build for the first time -- and leaked the real
# build machine's username/home path into `fossh-agent` via C++
# debug-info strings, a real, reproduced leak (found by this project's
# own comprehensive-pass QA, not assumed). `crates/fossh-quiche-ffi`'s
# separate vendored BoringSSL build (for the OCaml watchdog's ctypes
# side) already had this exact fix; this is the same fix for
# BoringSSL's *other*, independent build path.
export CFLAGS="${CFLAGS:-} -ffile-prefix-map=${project_root}=/build/fossh -ffile-prefix-map=${cargo_home}=/build/cargo-registry"
export CXXFLAGS="${CXXFLAGS:-} -ffile-prefix-map=${project_root}=/build/fossh -ffile-prefix-map=${cargo_home}=/build/cargo-registry"

echo "build-release: remapping '${project_root}' -> /build/fossh"
echo "build-release: remapping '${cargo_home}' -> /build/cargo-registry"

cd "$project_root"
# --features fossh-fcgi/quic,fossh-agent/quic: without this, the §3.4
# QUIC channel (watchdog reload/status) compiles into neither shipped
# binary at all — the feature is off by default deliberately (heavy
# BoringSSL compile no ordinary `cargo build --workspace` should pay
# for, see ADR-0050 Part 3 and fossh-agent/Cargo.toml's own comment),
# but a *release* build is exactly the one build that must pay it, or
# the whole channel is dead code in what actually ships. Package-
# qualified syntax, not a bare `--features quic`: unambiguous about
# which crates it applies to regardless of workspace feature
# resolution, and correct even if only one of the two crates were to
# gain an unrelated same-named feature later.
cargo build --release --workspace --features fossh-fcgi/quic,fossh-agent/quic
(cd crates/fossh-ffi && cargo build --release)

echo "build-release: done. Verify with scripts/check-identity-hygiene.sh."
