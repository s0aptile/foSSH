#!/bin/sh
# Builds libquiche.{so,a} + quiche.h for the OCaml watchdog's ctypes
# bindings (§2.2/§3.4) to link against.
#
# quiche's own C ABI (src/ffi.rs, gated behind its `ffi` Cargo
# feature) lives in a *private* Rust module (`mod ffi;`, not `pub mod
# ffi;`). Its `#[no_mangle] pub extern "C" fn`s only get real ELF
# visibility in a built cdylib/staticlib when quiche itself is the
# crate being compiled directly to that crate-type — not when it's a
# dependency of some other wrapper crate. Confirmed empirically, not
# assumed: a wrapper crate depending on quiche (features = ["ffi"])
# produced a `.so` exporting zero `quiche_*` symbols (`nm -D | grep
# quiche_` — nothing); building quiche's own source directly, same
# feature flag, exported all 170. This is why
# crates/fossh-quiche-ffi/Cargo.toml is never `cargo build`'d directly
# — it exists purely to pin quiche's exact version in a real,
# auditable Cargo.lock, which this script resolves via `cargo
# metadata` and then vendors into a throwaway build directory (never
# committed — see .gitignore) and builds separately, the same way
# quiche's own upstream build instructions do it.
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
pin_crate="$project_root/crates/fossh-quiche-ffi"
build_dir="$pin_crate/vendor-build"
out_dir="$pin_crate/dist"

echo "build-quiche-ffi: resolving the pinned quiche version" >&2
cd "$pin_crate"
cargo fetch >&2

quiche_manifest=$(cargo metadata --format-version 1 2>/dev/null \
  | jq -r '.packages[] | select(.name == "quiche") | .manifest_path')
quiche_src=$(dirname "$quiche_manifest")

echo "build-quiche-ffi: vendoring $quiche_src -> $build_dir" >&2
rm -rf "$build_dir"
mkdir -p "$build_dir"
cp -r "$quiche_src"/. "$build_dir"/
# The registry cache's copy is read-only; cargo's own build (target/,
# intermediate build.rs output) needs to write into this tree.
chmod -R u+w "$build_dir"
# Marks the vendored copy as its own workspace root, stopping cargo's
# upward search — without this, cargo finds the pin crate's workspace
# above it, sees vendor-build/ isn't a listed member, and refuses to
# build at all ("believes it's in a workspace when it's not").
printf '\n[workspace]\n' >> "$build_dir/Cargo.toml"

echo "build-quiche-ffi: building (this compiles BoringSSL from source via cmake — expect it to take a while the first time)" >&2
(cd "$build_dir" && cargo build --release --features ffi)

mkdir -p "$out_dir/lib" "$out_dir/include"
cp "$build_dir/target/release/libquiche.so" "$out_dir/lib/"
cp "$build_dir/target/release/libquiche.a" "$out_dir/lib/"
cp "$build_dir/include/quiche.h" "$out_dir/include/"

echo "build-quiche-ffi: done" >&2
echo "  $out_dir/lib/libquiche.so" >&2
echo "  $out_dir/lib/libquiche.a" >&2
echo "  $out_dir/include/quiche.h" >&2
