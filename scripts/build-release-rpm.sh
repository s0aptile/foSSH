#!/bin/sh
# Builds fossh's RPM + SRPM via a real `rpmbuild`, with `_topdir` and
# `_buildhost` overridden so neither the real build machine's home-
# directory path nor its hostname leaks into package metadata —
# rpmbuild's own defaults do both otherwise, confirmed real (13+
# `strings` hits from a bare `rpmbuild -bb`/`-bs` against this exact
# spec, on this exact machine — see DECISIONS.md ADR-0054). Neither
# leak is `packaging/rpm/fossh.spec`'s own fault; both are generated
# by rpmbuild itself, driven entirely by these two defaults. Run this
# instead of a bare `rpmbuild -ba` against that spec.
#
# `--nodeps`: this dev environment's Rust is rustup-managed, not the
# system `cargo`/`rust` RPMs the spec's own `BuildRequires` names —
# expected here, not a bug in the spec (see dev/DURUM.md). A real
# Fedora build host (or Koji/mock) with those RPMs installed should
# build without it.
#
# If `ocaml-ctypes`/`ocaml-findlib` aren't installed as system RPMs
# (true on this dev machine as of this writing), rpmbuild's `%build`
# needs the local opam switch's env (OCAMLPATH etc.) to find them —
# the spec's own `%build` deliberately doesn't source it itself, since
# a real Fedora build host is expected to have the system packages
# instead. Reproduced for real once already: a first run of this exact
# script, without this block, failed `dune build` inside rpmbuild's
# isolated %build with "Library integers not found" — rpmbuild's child
# process doesn't inherit an opam env nobody activated in its parent.
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tag=fossh-0.2.0-alpha.1

if [ -d "$project_root/watchdog/_opam" ]; then
  echo "build-release-rpm: local opam switch found — sourcing its env for %build" >&2
  eval "$(cd "$project_root/watchdog" && opam env)"
fi

# mktemp -d, not "$project_root/dist/rpmbuild": this project's own
# checkout necessarily lives under the real user's home directory, so
# ANY path built from $project_root still contains the real username
# as a substring — the exact false-clean mistake already made and
# caught once (see DECISIONS.md ADR-0054's own first verification
# attempt). A plain /tmp entry has no such risk.
topdir=$(mktemp -d)
trap 'rm -rf "$topdir"' EXIT
mkdir -p "$topdir/SOURCES" "$topdir/SPECS" "$topdir/BUILD" "$topdir/RPMS" "$topdir/SRPMS" "$topdir/BUILDROOT"

echo "build-release-rpm: building the source tarball" >&2
# HEAD alone would silently drop uncommitted tracked-file changes from the
# tarball (reproduced here: HEAD was still 0.1.0-alpha.1 while the working
# tree, and this spec copy below, were already 0.1.2-alpha.1).
#
# `git stash create` (the original approach here) snapshots the current
# INDEX+worktree into a real commit object without touching HEAD, the
# real index, or the stash list -- but it fundamentally cannot include
# untracked files, a real git limitation, not a flag we forgot. Found by
# this project's first real clean-VM install verification: new untracked
# files (watchdog/lib/operator_key.{ml,mli}, operator_auth_server.{ml,mli})
# were silently missing from the tarball while already-tracked files
# elsewhere referenced them, so rpmbuild's own isolated %build failed with
# "Unbound module Operator_auth_server" -- a real, reproduced bug this
# workaround-in-a-workaround exists to close.
#
# Fixed with a scratch index (GIT_INDEX_FILE pointed at a throwaway file,
# never the real one) seeded from HEAD then `add -A`'d exactly the way a
# real `git add -A` would -- picking up untracked files while still
# respecting .gitignore, so PUBLISH.md/private-onlyauthor/ etc. still
# correctly never enter this snapshot. Still never touches HEAD, the real
# index, or the stash list.
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
find "$topdir/RPMS" "$topdir/SRPMS" -name '*.rpm' -exec cp {} "$project_root/dist/" \;

echo "build-release-rpm: done, clean. Packages in dist/." >&2
