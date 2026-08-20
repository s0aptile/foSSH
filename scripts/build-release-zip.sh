#!/bin/sh

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

scratch_index=$(mktemp)
GIT_INDEX_FILE="$scratch_index" git -C "$project_root" read-tree HEAD

GIT_INDEX_FILE="$scratch_index" git -C "$project_root" ls-files -z -- ':!RULES.md' \
  | (cd "$stage/fossh" && xargs -0 -I{} sh -c 'mkdir -p "$(dirname "{}")" && cp "'"$project_root"'/{}" "{}"')
rm -f "$scratch_index"

mkdir -p "$stage/fossh/dist"

for f in "$project_root"/dist/*.rpm; do
  [ -f "$f" ] && cp "$f" "$stage/fossh/dist/"
done
if [ -f "$project_root/target/release/fossh-cgi" ]; then
  cp "$project_root/target/release/fossh-cgi" "$stage/fossh/dist/fossh-cgi-x86_64-unknown-linux-gnu"
  cp "$project_root/target/release/fossh" "$stage/fossh/dist/fossh-x86_64-unknown-linux-gnu"
  cp "$project_root/target/release/fossh-agent" "$stage/fossh/dist/fossh-agent-x86_64-unknown-linux-gnu"
fi
if [ -f "$project_root/crates/fossh-ffi/target/release/libfossh.so" ]; then
  cp "$project_root/crates/fossh-ffi/target/release/libfossh.so" "$stage/fossh/dist/"
  cp "$project_root/crates/fossh-ffi/target/release/libfossh.a" "$stage/fossh/dist/"
fi
cp "$project_root/include/fossh.h" "$stage/fossh/dist/"

cp "$project_root/readme.md" "$stage/readme.md"
cp "$project_root/tos.md" "$stage/tos.md"

( cd "$stage" && find fossh -type f | LC_ALL=C sort | xargs sha256sum ) > "$stage/SHA256SUMS"

touch -t 198001010000 "$work/mtime-ref"
find "$stage" -exec touch -r "$work/mtime-ref" {} +

rm -f "$zip_path"
( cd "$stage" && find . -type f | LC_ALL=C sort | sed 's|^\./||' | zip -X -6 -q "$zip_path" -@ )

echo "$zip_path"
sha256sum "$zip_path"
echo "uncompressed size: $(du -sb "$stage" | cut -f1) bytes, $(find "$stage" -type f | wc -l) files"
