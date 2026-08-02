#!/bin/sh
# Proves scripts/check-identity-hygiene.sh actually catches something,
# rather than trusting a clean run against the real repo at face value
# — the same "deliberate-failure test" pattern §17 already requires
# for the SQL-concatenation grep gate, applied here per §19.4.12's
# explicit "prove the gate works with a deliberate-failure test."
#
# Builds a throwaway git repo with a deliberately bad commit (a real-
# looking author identity, a real-shaped home path, and an unquoted
# $0aptile in a .sh file) and asserts the gate fails on it — then
# does the same for a clean fixture and asserts the gate passes.
# Touches nothing in the real repository.

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
echo "author: '$0aptile'"
EOF
git add -A
# --reset-author: plain `--amend` preserves the *original* author
# identity by default (only the message changes) — without this flag
# the fixture would still fail on author identity alone, which would
# be a bug in this test harness, not a real finding about the gate.
git commit -q --amend --reset-author -m "cleaned fixture commit"

if "$gate"; then
  echo "ok — gate correctly passed the cleaned fixture"
else
  echo "TEST FAILED: the gate failed a fixture that should be clean"
  exit 1
fi

echo
echo "test-identity-hygiene-gate: both directions verified"
