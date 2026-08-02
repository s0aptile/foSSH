#!/bin/sh
# §19.4.12's identity-hygiene gate. Deliberately generic and public:
# this script does *not* itself contain the author's real name, email,
# or username — hardcoding those into a public, committed script would
# just relocate the exact leak it exists to catch into the gate
# itself. Always checks the patterns that need no real-identity
# knowledge to be meaningful (the expected pseudonymous git identity,
# real-looking home-directory paths, this machine's hostname, the
# `$0aptile` shell-quoting gate). Optionally also checks whatever
# extended-regex alternation is in `$FOSSH_HYGIENE_EXTRA_PATTERNS` —
# populate that locally (never commit it) before a release, or from a
# GitHub Actions repository secret in real CI, to additionally check
# for the real name/email specifically. Safe, and still useful, to run
# with it unset.
#
# Run from the repository root. Exits non-zero on any failure —
# scripts/test-identity-hygiene-gate.sh proves this script actually
# catches something, rather than trusting a clean run at face value.

set -eu

fail=0

# This script and its own test harness are excluded from the two
# generic sweeps below, not from the whole gate: both files legitimately
# need to *contain* pattern-shaped example text (this script's own
# regex source; the test harness's deliberately-bad fixture strings,
# written into a throwaway temp repo at runtime, not meant to describe
# anything about *this* tree) — scanning them for their own tooling
# text is a guaranteed, uninteresting false positive, not a finding.
self_exclude='scripts/check-identity-hygiene.sh|scripts/test-identity-hygiene-gate.sh'

echo "== git author/committer identity =="
identities=$(git log --format='%an <%ae>%n%cn <%ce>' 2>/dev/null | sort -u)
echo "$identities"
if [ "$identities" != '$0aptile <s0aptile@users.noreply.github.com>' ]; then
  echo "FAIL: unexpected git identity in history (expected only the pseudonymous one)"
  fail=1
fi

echo "== generic real-path-shape sweep (/home/<user>/, /Users/<user>/) =="
if git ls-files -z | grep -zvE "$self_exclude" | xargs -0 grep -InE '/home/[^/ ]+/|/Users/[^/ ]+/' 2>/dev/null; then
  echo "FAIL: a real-looking home-directory path was found above"
  fail=1
else
  echo "clean"
fi

echo "== this machine's hostname =="
host=$(hostname 2>/dev/null || true)
if [ -n "$host" ] && git ls-files -z | grep -zvE "$self_exclude" | xargs -0 grep -Iln -F "$host" 2>/dev/null; then
  echo "FAIL: this machine's hostname ($host) appears in the tree"
  fail=1
else
  echo "clean"
fi

if [ -n "${FOSSH_HYGIENE_EXTRA_PATTERNS:-}" ]; then
  echo "== author-supplied extra patterns =="
  if git ls-files -z | grep -zvE "$self_exclude" | xargs -0 grep -InE "$FOSSH_HYGIENE_EXTRA_PATTERNS" 2>/dev/null; then
    echo "FAIL: an author-supplied sensitive pattern was found above"
    fail=1
  else
    echo "clean"
  fi
else
  echo "(FOSSH_HYGIENE_EXTRA_PATTERNS unset — skipping author-specific patterns; set it locally before a release, or as a repository secret in CI, to actually check for the real name/email)"
fi

echo "== \$0aptile unquoted in shell/Make/CI contexts =="
# A bare (unescaped, un-single-quoted) \$0 undergoes shell expansion —
# to the script's own name — in *both* an unquoted context and inside
# double quotes (double quotes do not block \$-expansion; only single
# quotes or a backslash do). The two sanctioned safe forms are
# therefore: backslash-escaped (\$0aptile, safe anywhere, including
# inside double quotes), or wrapped in single quotes on a line that
# contains no double-quote character at all (a single quote *nested*
# inside a double-quoted string is just a literal apostrophe in real
# shell semantics — it does not suppress expansion, and is treated as
# a violation here, not a safe form, on purpose).
violation=0
for f in $(git ls-files '*.sh' 'Makefile' '.github/workflows/*.yml' '.github/workflows/*.yaml' 2>/dev/null | grep -vE "$self_exclude"); do
  line_no=0
  while IFS= read -r line || [ -n "$line" ]; do
    line_no=$((line_no + 1))
    case "$line" in
      *'$0aptile'*) : ;; # contains the literal token somewhere — inspect further
      *) continue ;;
    esac
    case "$line" in
      *'\$0aptile'*) continue ;; # escaped: safe anywhere
    esac
    case "$line" in
      *'"'*) ;; # a double quote is present: single-quote nesting would not actually help — fall through to the failure below
      *"'"'$0aptile'"'"*) continue ;; # single-quoted, and no double quote on the line at all: safe
    esac
    echo "FAIL: unquoted/unescaped \$0aptile in $f:$line_no: $line"
    violation=1
  done < "$f"
done
if [ "$violation" -eq 1 ]; then
  fail=1
else
  echo "clean (or no .sh/Makefile/CI-workflow files exist yet to check)"
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "release-hygiene: FAILED"
  exit 1
fi
echo "release-hygiene: all checks passed"
