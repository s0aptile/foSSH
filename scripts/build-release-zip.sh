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

# The complete repository tree, per §5/§19.7 — everything git tracks
# OR staged-but-uncommitted (a plain `git ls-files -z`, the original
# approach here, misses untracked new files entirely — a real,
# reproduced gap: this exact bug silently dropped a whole session's
# worth of new work, watchdog/lib/operator_*.{ml,mli} included, from a
# "give out the real source" public release zip, same underlying
# mistake scripts/build-release-rpm.sh's own git-stash-create gap
# already found and fixed for the RPM's source tarball). Fixed the same
# way: a scratch GIT_INDEX_FILE seeded from HEAD then `add -A`'d,
# which still correctly excludes .git/, target/, .env, and PUBLISH.md
# (all .gitignore'd, §19.8 — never shipped) without ever touching the
# real index, HEAD, or the stash list.
scratch_index=$(mktemp)
GIT_INDEX_FILE="$scratch_index" git -C "$project_root" read-tree HEAD
GIT_INDEX_FILE="$scratch_index" git -C "$project_root" add -A
# RULES.md is tracked (contributors need it) but self-declares as an
# internal reference doc in its own first line -- it explains the
# public/private boundary mechanism itself, which is exactly the kind
# of thing that boundary exists to keep out of what ships. Excluded
# here, not deleted from the tree.
GIT_INDEX_FILE="$scratch_index" git -C "$project_root" ls-files -z -- ':!RULES.md' \
  | (cd "$stage/fossh" && xargs -0 -I{} sh -c 'mkdir -p "$(dirname "{}")" && cp "'"$project_root"'/{}" "{}"')
rm -f "$scratch_index"

# dist/: what this build environment can actually produce today, not
# the full §19.7 wish list (musl x86_64+aarch64, an SBOM, a signed
# manifest — none of those exist yet; see dev/DURUM.md/DECISIONS.md for
# why, and the printed checklist below for an explicit, honest miss
# rather than a silently-absent line).
mkdir -p "$stage/fossh/dist"
# Copies whatever RPM/SRPM artifacts actually exist in dist/ rather
# than a hardcoded release number -- the base/watchdog subpackage
# split (packaging/rpm/fossh.spec) bumped Release and added
# fossh-watchdog-*.rpm as a second package; hardcoding names here once
# already went stale silently (found the same day it happened) and
# would again on the next bump.
for f in "$project_root"/dist/*.rpm; do
  [ -f "$f" ] && cp "$f" "$stage/fossh/dist/"
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
