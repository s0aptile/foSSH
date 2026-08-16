#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
gate="$script_dir/check-identity-hygiene.sh"
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT

cd "$fixture"
git init -q
git config user.name "Not The Pseudonym"
git config user.email "real.person@example.com"

mkdir -p sub
cat > sub/leaky.md <<'EOF'
Built at /home/reallyarealuser/project/target/release/fossh-cgi
EOF
cat > bad.sh <<'EOF'
#!/bin/sh
echo "author: $0aptile"
EOF
git add -A
git commit -q -m "deliberately bad fixture commit"

echo "=== deliberately bad fixture: gate must FAIL ==="
if "$gate"; then
  echo "TEST FAILED: the gate passed a fixture that should have failed it"
  exit 1
fi
echo "ok — gate correctly failed on the bad fixture"

echo
echo "=== cleaning the fixture: gate must then PASS ==="
git config user.name '$0aptile'
git config user.email 's0aptile@users.noreply.github.com'
rm sub/leaky.md
cat > bad.sh <<'EOF'
#!/bin/sh
# Backslash-escaped, the actually-correct safe form inside a
# double-quoted string — a single quote nested *inside* double quotes
# is only a literal apostrophe in real shell semantics, it does not
# suppress $-expansion, and an earlier draft of this fixture used that
# broken form by mistake, which the gate correctly kept failing until
# it was fixed to this.
echo "author: \$0aptile"
EOF
git add -A

git commit -q --amend --reset-author -m "cleaned fixture commit"

if "$gate"; then
  echo "ok — gate correctly passed the cleaned fixture"
else
  echo "TEST FAILED: the gate failed a fixture that should be clean"
  exit 1
fi

echo
echo "test-identity-hygiene-gate: both directions verified"
