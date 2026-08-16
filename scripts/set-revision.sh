#!/bin/sh

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

for f in Cargo.toml \
         crates/fossh-ffi/Cargo.toml \
         crates/fossh-ipc/Cargo.toml \
         crates/fossh-quiche-ffi/Cargo.toml; do
    [ -f "$f" ] || continue
    sed -i -E "s|^version = \"[^\"]+\"|version = \"$cargo_version\"|" "$f"
done

sed -i -E "s|^%global srcversion .*|%global srcversion $display|" packaging/rpm/fossh.spec
sed -i -E "s|^Version:( +).*|Version:\1$display|" packaging/rpm/fossh.spec

sed -i -E "s|^tag=fossh-.*|tag=fossh-$display|" scripts/build-release-rpm.sh

if [ -f bindings/ruby/lib/fossh/version.rb ]; then
    sed -i -E "s|VERSION = \"[^\"]+\"|VERSION = \"$display\"|" bindings/ruby/lib/fossh/version.rb
fi

sed -i -E "s|fossh-advisor:[0-9][^\"]*|fossh-advisor:$display|" crates/fossh-selfheal/src/advisor.rs
sed -i -E "s|fossh-advisor:[0-9][0-9.]*|fossh-advisor:$display|" packaging/model/Modelfile
sed -i -E "s|fossh-advisor:[0-9][0-9.]*|fossh-advisor:$display|g" docs/SELF-HEALING.md

sed -i -E "s|fossh-witness:[0-9][0-9.]*|fossh-witness:$display|" packaging/model/Modelfile.witness

sed -i -E "s|^REVISION = \"[0-9][0-9.]*\"|REVISION = \"$display\"|" gui/fossh_console/advisor_client.py

sed -i -E "s|foSSH-Verify/[0-9][0-9.]*|foSSH-Verify/$display|" gui/fossh_console/verify.py

awk -v v="$display" '
    !done && /<release version="/ { sub(/<release version="[^"]+"/, "<release version=\"" v "\""); done = 1 }
    { print }
' gui/data/org.fossh.Console.metainfo.xml > gui/data/org.fossh.Console.metainfo.xml.tmp
mv gui/data/org.fossh.Console.metainfo.xml.tmp gui/data/org.fossh.Console.metainfo.xml

sed -i -E "s|\*\*Status: open alpha \(\`[0-9][0-9.]*\`\)\.\*\*|**Status: open alpha (\`$display\`).**|" README.md

cargo update --workspace --offline >/dev/null 2>&1 || cargo update --workspace >/dev/null 2>&1 || true

echo "revision set to $display" >&2
echo "  cargo:   $cargo_version" >&2
echo "  rpm:     1:$display  (epoch 1 — see this script's header)" >&2
echo "  models:  fossh-advisor:$display, fossh-witness:$display" >&2
echo >&2
echo "Remaining by hand, deliberately: a %changelog entry in" >&2
echo "packaging/rpm/fossh.spec saying what this revision changed." >&2
