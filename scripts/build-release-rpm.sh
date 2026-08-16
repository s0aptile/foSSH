#!/bin/sh

set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tag=fossh-0.0.2.2

if [ -d "$project_root/watchdog/_opam" ]; then
  echo "build-release-rpm: local opam switch found — sourcing its env for %build" >&2
  eval "$(cd "$project_root/watchdog" && opam env)"
fi

topdir=$(mktemp -d)
trap 'rm -rf "$topdir"' EXIT
mkdir -p "$topdir/SOURCES" "$topdir/SPECS" "$topdir/BUILD" "$topdir/RPMS" "$topdir/SRPMS" "$topdir/BUILDROOT"

echo "build-release-rpm: building the source tarball" >&2

scratch_index=$(mktemp)
trap 'rm -rf "$topdir" "$scratch_index"' EXIT
GIT_INDEX_FILE="$scratch_index" git -C "$project_root" read-tree HEAD
GIT_INDEX_FILE="$scratch_index" git -C "$project_root" add -A
snapshot_tree=$(GIT_INDEX_FILE="$scratch_index" git -C "$project_root" write-tree)
archive_ref=$(git -C "$project_root" commit-tree "$snapshot_tree" -p HEAD -m "build-release-rpm.sh snapshot")
git -C "$project_root" archive --prefix="${tag}/" -o "$topdir/SOURCES/${tag}.tar.gz" "${archive_ref:-HEAD}"
cp "$project_root/packaging/rpm/fossh.spec" "$topdir/SPECS/"

echo "build-release-rpm: remapping _topdir -> $topdir, _buildhost -> fossh-build" >&2
rpmbuild \
  --define "_topdir $topdir" \
  --define "_buildhost fossh-build" \
  -ba "$topdir/SPECS/fossh.spec" \
  --nodeps --nocheck

echo "build-release-rpm: verifying no real username/hostname leaked into the built packages" >&2
real_user=$(id -un)
real_host=$(hostname 2>/dev/null || true)
fail=0
for rpm in "$topdir"/RPMS/*/*.rpm "$topdir"/SRPMS/*.rpm; do
  [ -f "$rpm" ] || continue
  if strings "$rpm" | grep -qF "/home/${real_user}"; then
    echo "FAIL: $rpm contains the real username ($real_user)" >&2
    fail=1
  fi
  if [ -n "$real_host" ] && strings "$rpm" | grep -qF "$real_host"; then
    echo "FAIL: $rpm contains the real hostname ($real_host)" >&2
    fail=1
  fi
done
if [ "$fail" -ne 0 ]; then
  echo "build-release-rpm: identity leak found above — not copying to dist/, not shipping" >&2
  exit 1
fi

mkdir -p "$project_root/dist"

rm -f "$project_root"/dist/*.rpm

find "$topdir/RPMS" "$topdir/SRPMS" -name '*.rpm' -exec cp {} "$project_root/dist/" \;

echo "build-release-rpm: done, clean. Packages in dist/." >&2
