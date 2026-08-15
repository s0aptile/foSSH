#!/bin/sh
# Sets this project's revision number, everywhere, from one place.
#
#     scripts/set-revision.sh 3
#
# foSSH versions as `0.0.2.x`, where `0.0.2` is the line and `x` is a
# revision counter that goes up by one for each complete revision. That
# is the number a person sees: in `dnf`, in the console's About dialog,
# in the release archive's name.
#
# ## Why Cargo says something slightly different
#
# `0.0.2.1` is not a valid SemVer version — SemVer allows exactly three
# numeric components — and Cargo rejects it outright ("unexpected
# character '.' after patch version number", confirmed, not assumed).
# So Cargo carries `0.0.2+rev.N`, using SemVer's build-metadata field,
# and every user-facing surface renders `0.0.2.N`.
#
# Build metadata is the right field rather than a pre-release
# (`0.0.2-rev.N`): a pre-release sorts *below* `0.0.2`, which would
# claim every revision is something released before a `0.0.2` that is
# never going to exist. Build metadata is ignored for precedence, which
# is accurate here — nothing in this workspace resolves by version,
# every internal dependency is a path dependency.
#
# ## Why the RPM carries an Epoch
#
# `0.0.2.x` is numerically *lower* than the retired `0.1.3`, so without
# an epoch `dnf` sees a downgrade and will not offer the upgrade at
# all. `Epoch: 1` is exactly what epochs exist for. Verified:
#
#     rpmdev-vercmp 0.1.3~alpha.1-2 0.0.2.1-1     -> 0.1.3 is GREATER
#     rpmdev-vercmp 0:0.1.3~alpha.1-2 1:0.0.2.1-1 -> 0.0.2.1 is GREATER
#
# The epoch is set once, in the spec, and never needs to change again.
# Removing it would silently strand every 0.1.x install.
set -eu

if [ $# -ne 1 ]; then
    echo "usage: $0 <revision>    (a non-negative integer; the x in 0.0.2.x)" >&2
    exit 2
fi

rev=$1
case "$rev" in
    ''|*[!0-9]*)
        echo "$0: revision must be a non-negative integer, got '$rev'" >&2
        exit 2
        ;;
esac

line=0.0.2
display="$line.$rev"
cargo_version="$line+rev.$rev"

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

# Every Cargo.toml carrying a literal version. The workspace root sets
# `version` under [workspace.package]; the three excluded crates
# (fossh-ffi, fossh-ipc, fossh-quiche-ffi are deliberately not
# workspace members — see the root Cargo.toml) each carry their own.
for f in Cargo.toml \
         crates/fossh-ffi/Cargo.toml \
         crates/fossh-ipc/Cargo.toml \
         crates/fossh-quiche-ffi/Cargo.toml; do
    [ -f "$f" ] || continue
    sed -i -E "s|^version = \"[^\"]+\"|version = \"$cargo_version\"|" "$f"
done

# The RPM. `srcversion` names the source tarball and the directory
# inside it; `Version:` is what rpm compares. They are allowed to
# differ in shape (Version cannot contain a '-') but here they do not
# need to.
sed -i -E "s|^%global srcversion .*|%global srcversion $display|" packaging/rpm/fossh.spec
sed -i -E "s|^Version:( +).*|Version:\1$display|" packaging/rpm/fossh.spec

# The tarball prefix the RPM build script hands to `git archive` has to
# match `srcversion`, or %prep unpacks into a directory %build cannot
# find.
sed -i -E "s|^tag=fossh-.*|tag=fossh-$display|" scripts/build-release-rpm.sh

# The Ruby binding advertises its own version to the applications that
# embed it.
if [ -f bindings/ruby/lib/fossh/version.rb ]; then
    sed -i -E "s|VERSION = \"[^\"]+\"|VERSION = \"$display\"|" bindings/ruby/lib/fossh/version.rb
fi

# The derived model is tagged with the revision that produced it, so an
# install running one revision against a model built by another is
# visible rather than silent. `advisor.rs` and the Modelfile must agree
# — there is a test asserting exactly that.
sed -i -E "s|fossh-advisor:[0-9][^\"]*|fossh-advisor:$display|" crates/fossh-selfheal/src/advisor.rs
sed -i -E "s|fossh-advisor:[0-9][0-9.]*|fossh-advisor:$display|" packaging/model/Modelfile
sed -i -E "s|fossh-advisor:[0-9][0-9.]*|fossh-advisor:$display|g" docs/SELF-HEALING.md

# What the integration-verification browser calls itself, so an
# operator can identify the visit in their own data.
sed -i -E "s|foSSH-Verify/[0-9][0-9.]*|foSSH-Verify/$display|" gui/fossh_console/verify.py

# The software-centre listing.
sed -i -E "s|<release version=\"[^\"]+\"|<release version=\"$display\"|" \
    gui/data/org.fossh.Console.metainfo.xml

# Cargo.lock records the workspace members' own versions.
cargo update --workspace --offline >/dev/null 2>&1 || cargo update --workspace >/dev/null 2>&1 || true

echo "revision set to $display" >&2
echo "  cargo:   $cargo_version" >&2
echo "  rpm:     1:$display  (epoch 1 — see this script's header)" >&2
echo "  model:   fossh-advisor:$display" >&2
echo >&2
echo "Remaining by hand, deliberately: a %changelog entry in" >&2
echo "packaging/rpm/fossh.spec saying what this revision changed." >&2
