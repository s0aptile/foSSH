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

echo "build-release: remapping '${project_root}' -> /build/fossh"
echo "build-release: remapping '${cargo_home}' -> /build/cargo-registry"

cd "$project_root"
cargo build --release --workspace
(cd crates/fossh-ffi && cargo build --release)

echo "build-release: done. Verify with scripts/check-identity-hygiene.sh."
