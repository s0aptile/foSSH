#!/bin/sh

set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_root"

out_dir="${1:-$project_root/dist}"
mkdir -p "$out_dir"
zip_path="$out_dir/fossh-documents.zip"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

stage="$work/stage"
mkdir -p "$stage/docs"

scratch_index=$(mktemp)
GIT_INDEX_FILE="$scratch_index" git -C "$project_root" read-tree HEAD

GIT_INDEX_FILE="$scratch_index" git -C "$project_root" ls-files -z -- \
  AUTHORS LICENSE NOTICE PRIVACY.md SECURITY.md THREAT_MODEL.md tos.md \
  RETIREMENT.md docs/SELF-HEALING.md docs/UPGRADING-from-0.1.md \
  | (cd "$stage" && xargs -0 -I{} sh -c 'mkdir -p "$(dirname "{}")" && cp "'"$project_root"'/{}" "{}"')
rm -f "$scratch_index"

touch -t 198001010000 "$work/mtime-ref"
find "$stage" -exec touch -r "$work/mtime-ref" {} +

rm -f "$zip_path"
( cd "$stage" && find . -type f | LC_ALL=C sort | sed 's|^\./||' | zip -X -6 -q "$zip_path" -@ )

echo "$zip_path"
sha256sum "$zip_path"
echo "files: $(find "$stage" -type f | wc -l)"
