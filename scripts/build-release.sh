#!/bin/sh

set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cargo_home="${CARGO_HOME:-$HOME/.cargo}"

export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=${project_root}=/build/fossh --remap-path-prefix=${cargo_home}=/build/cargo-registry"

openssl_libdir=$(pkg-config --variable=libdir openssl 2>/dev/null || true)
if [ -n "$openssl_libdir" ] && [ -e "${openssl_libdir}/libcrypto.so" ]; then
    export RUSTFLAGS="${RUSTFLAGS} -C link-arg=${openssl_libdir}/libcrypto.so"
else

    for candidate in /usr/lib64/libcrypto.so /usr/lib/x86_64-linux-gnu/libcrypto.so /usr/lib/libcrypto.so; do
        if [ -e "$candidate" ]; then
            openssl_libdir=$(dirname "$candidate")
            break
        fi
    done
    if [ -n "$openssl_libdir" ] && [ -e "${openssl_libdir}/libcrypto.so" ]; then
        echo "build-release: pkg-config could not answer; using ${openssl_libdir}/libcrypto.so found directly" >&2
        export RUSTFLAGS="${RUSTFLAGS} -C link-arg=${openssl_libdir}/libcrypto.so"
    else
        echo "build-release: cannot find the system libcrypto.so." >&2
        echo "build-release:" >&2
        echo "build-release:   This build links BoringSSL (via quiche, for the watchdog" >&2
        echo "build-release:   channel) and SQLCipher (via rusqlite, for data at rest) into" >&2
        echo "build-release:   the same binaries. BoringSSL ships its own file named" >&2
        echo "build-release:   libcrypto.a on the linker's -L path and does not implement" >&2
        echo "build-release:   the OpenSSL 3 EVP_MAC family SQLCipher needs, so the real" >&2
        echo "build-release:   libcrypto.so has to be named explicitly or the link fails" >&2
        echo "build-release:   with undefined EVP_MAC_* symbols." >&2
        echo "build-release:" >&2
        echo "build-release:   Install openssl-devel (and pkgconf-pkg-config), then re-run." >&2
        exit 1
    fi
fi

export CFLAGS="${CFLAGS:-} -ffile-prefix-map=${project_root}=/build/fossh -ffile-prefix-map=${cargo_home}=/build/cargo-registry"
export CXXFLAGS="${CXXFLAGS:-} -ffile-prefix-map=${project_root}=/build/fossh -ffile-prefix-map=${cargo_home}=/build/cargo-registry"

echo "build-release: remapping '${project_root}' -> /build/fossh"
echo "build-release: remapping '${cargo_home}' -> /build/cargo-registry"

cd "$project_root"

cargo build --release --workspace --features fossh-fcgi/quic,fossh-agent/quic
(cd crates/fossh-ffi && cargo build --release)

echo "build-release: done. Verify with scripts/check-identity-hygiene.sh."
