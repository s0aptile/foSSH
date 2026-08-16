#!/bin/sh

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

chmod -R u+w "$build_dir"

printf '\n[workspace]\n' >> "$build_dir/Cargo.toml"

echo "build-quiche-ffi: building (this compiles BoringSSL from source via cmake — expect it to take a while the first time)" >&2
cargo_home="${CARGO_HOME:-$HOME/.cargo}"

(cd "$build_dir" \
  && RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=${build_dir}=/build/quiche --remap-path-prefix=${cargo_home}=/build/cargo-registry" \
     CFLAGS="${CFLAGS:-} -ffile-prefix-map=${cargo_home}=/build/cargo-registry -ffile-prefix-map=${build_dir}=/build/quiche" \
     CXXFLAGS="${CXXFLAGS:-} -ffile-prefix-map=${cargo_home}=/build/cargo-registry -ffile-prefix-map=${build_dir}=/build/quiche" \
     cargo build --release --features ffi)

mkdir -p "$out_dir/lib" "$out_dir/include"
cp "$build_dir/target/release/libquiche.so" "$out_dir/lib/"
cp "$build_dir/target/release/libquiche.a" "$out_dir/lib/"
cp "$build_dir/include/quiche.h" "$out_dir/include/"

watchdog_vendor="$project_root/watchdog/quic/vendor"
mkdir -p "$watchdog_vendor"

cp "$out_dir/lib/libquiche.so" "$watchdog_vendor/"
cp "$out_dir/include/quiche.h" "$watchdog_vendor/"

ln -sf libquiche.so "$watchdog_vendor/libquiche.so.0"

echo "build-quiche-ffi: done" >&2
echo "  $out_dir/lib/libquiche.so" >&2
echo "  $out_dir/lib/libquiche.a" >&2
echo "  $out_dir/include/quiche.h" >&2
echo "  $watchdog_vendor/libquiche.so" >&2
echo "  $watchdog_vendor/libquiche.so.0 (symlink)" >&2
echo "  $watchdog_vendor/quiche.h" >&2
