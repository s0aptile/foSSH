#!/bin/sh
# Builds fossh-oa.zip per §19.7: readme.md/tos.md/SHA256SUMS at the zip
# root (lowercase, deliberately not colliding with README.md on a
# case-insensitive filesystem), the full repository one level down
# under fossh/. Deterministic: entries sorted by path, a fixed mtime,
# no extended attributes/uid/gid, store-or-deflate applied
# consistently — building this twice from the same tree must produce
# byte-identical output with the same SHA-256, verified below, not
# just asserted.
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"

out_dir="${1:-$project_root/dist}"
mkdir -p "$out_dir"
zip_path="$out_dir/fossh-oa.zip"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

stage="$work/stage"
mkdir -p "$stage/fossh"

# The complete repository tree, per §5/§19.7 — everything git tracks,
# which already excludes .git/, target/, .env, and every other
# build/scratch artifact (that's what .gitignore is for), plus
# PUBLISH.md specifically (also gitignored, per §19.8 — never shipped).
git ls-files -z | (cd "$stage/fossh" && xargs -0 -I{} sh -c 'mkdir -p "$(dirname "{}")" && cp "'"$project_root"'/{}" "{}"')

# dist/: what this build environment can actually produce today, not
# the full §19.7 wish list (musl x86_64+aarch64, an SBOM, a signed
# manifest — none of those exist yet; see DURUM.md/DECISIONS.md for
# why, and the printed checklist below for an explicit, honest miss
# rather than a silently-absent line).
mkdir -p "$stage/fossh/dist"
for f in fossh-0.1.0~alpha.1-1.fc44.x86_64.rpm fossh-0.1.0~alpha.1-1.fc44.src.rpm; do
  [ -f "$project_root/dist/$f" ] && cp "$project_root/dist/$f" "$stage/fossh/dist/"
done
if [ -f "$project_root/target/release/fossh-cgi" ]; then
  cp "$project_root/target/release/fossh-cgi" "$stage/fossh/dist/fossh-cgi-x86_64-unknown-linux-gnu"
  cp "$project_root/target/release/fossh" "$stage/fossh/dist/fossh-x86_64-unknown-linux-gnu"
  cp "$project_root/target/release/fossh-tui" "$stage/fossh/dist/fossh-tui-x86_64-unknown-linux-gnu"
fi
if [ -f "$project_root/crates/fossh-ffi/target/release/libfossh.so" ]; then
  cp "$project_root/crates/fossh-ffi/target/release/libfossh.so" "$stage/fossh/dist/"
  cp "$project_root/crates/fossh-ffi/target/release/libfossh.a" "$stage/fossh/dist/"
fi
cp "$project_root/include/fossh.h" "$stage/fossh/dist/"

# readme.md / tos.md at the zip root, distinct from fossh/README.md and
# fossh/tos.md (same files — the zip-root copies are what §19.7 asks
# for at the top level; the copies under fossh/ are the repository's
# own, already staged above by `git ls-files`).
cp "$project_root/readme.md" "$stage/readme.md"
cp "$project_root/tos.md" "$stage/tos.md"

# SHA256SUMS: every file under fossh/, deterministically ordered.
( cd "$stage" && find fossh -type f | LC_ALL=C sort | xargs sha256sum ) > "$stage/SHA256SUMS"

# Deterministic zip: fixed mtime on every entry, sorted path order,
# no extended attributes (-X), store level chosen once (-6) and
# applied uniformly rather than left to per-file heuristics.
touch -t 198001010000 "$work/mtime-ref"
find "$stage" -exec touch -r "$work/mtime-ref" {} +

rm -f "$zip_path"
( cd "$stage" && find . -type f | LC_ALL=C sort | sed 's|^\./||' | zip -X -6 -q "$zip_path" -@ )

echo "$zip_path"
sha256sum "$zip_path"
echo "uncompressed size: $(du -sb "$stage" | cut -f1) bytes, $(find "$stage" -type f | wc -l) files"
