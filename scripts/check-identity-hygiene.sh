#!/bin/sh

set -eu

fail=0

self_exclude='scripts/check-identity-hygiene.sh|scripts/test-identity-hygiene-gate.sh'

fossh_ls_files() {
  git ls-files -z --cached --others --exclude-standard
}

echo "== git author/committer identity =="
identities=$(git log --format='%an <%ae>%n%cn <%ce>' 2>/dev/null | sort -u)
echo "$identities"
if [ "$identities" != '$0aptile <s0aptile@users.noreply.github.com>' ]; then
  echo "FAIL: unexpected git identity in history (expected only the pseudonymous one)"
  fail=1
fi

echo "== generic real-path-shape sweep (/home/<user>, /Users/<user>) =="

home_path_matches=$(fossh_ls_files | grep -zvE "$self_exclude" | xargs -0 grep -InE '/home/[A-Za-z0-9_-]+|/Users/[A-Za-z0-9_-]+' 2>/dev/null || true)
if [ -n "$home_path_matches" ]; then
  echo "$home_path_matches"
  echo "FAIL: a real-looking home-directory path was found above"
  fail=1
else
  echo "clean"
fi

echo "== this machine's hostname =="
host=$(hostname 2>/dev/null || true)
hostname_matches=""
if [ -n "$host" ]; then
  hostname_matches=$(fossh_ls_files | grep -zvE "$self_exclude" | xargs -0 grep -Iln -F "$host" 2>/dev/null || true)
fi
if [ -n "$hostname_matches" ]; then
  echo "$hostname_matches"
  echo "FAIL: this machine's hostname ($host) appears in the tree"
  fail=1
else
  echo "clean"
fi

if [ -n "${FOSSH_HYGIENE_EXTRA_PATTERNS:-}" ]; then
  echo "== author-supplied extra patterns =="
  extra_matches=$(fossh_ls_files | grep -zvE "$self_exclude" | xargs -0 grep -InE "$FOSSH_HYGIENE_EXTRA_PATTERNS" 2>/dev/null || true)
  if [ -n "$extra_matches" ]; then
    echo "$extra_matches"
    echo "FAIL: an author-supplied sensitive pattern was found above"
    fail=1
  else
    echo "clean"
  fi
else
  echo "(FOSSH_HYGIENE_EXTRA_PATTERNS unset — skipping author-specific patterns; set it locally before a release, or as a repository secret in CI, to actually check for the real name/email)"
fi

echo "== \$0aptile unquoted in shell/Make/CI contexts =="

violation=0

filelist=$(mktemp)
trap 'rm -f "$filelist"' EXIT
fossh_ls_files | tr '\0' '\n' | grep -E '\.sh$|(^|/)Makefile$|\.github/workflows/.*\.ya?ml$' | grep -vE "$self_exclude" > "$filelist" || true
while IFS= read -r f; do
  [ -n "$f" ] || continue
  line_no=0
  while IFS= read -r line || [ -n "$line" ]; do
    line_no=$((line_no + 1))
    case "$line" in
      *'$0aptile'*) : ;;
      *) continue ;;
    esac

    stripped=$(printf '%s\n' "$line" | sed 's/\\\$0aptile//g')
    case "$stripped" in
      *'$0aptile'*) ;;
      *) continue ;;
    esac
    case "$line" in
      *'"'*) ;;
      *"'"'$0aptile'"'"*) continue ;;
    esac
    echo "FAIL: unquoted/unescaped \$0aptile in $f:$line_no: $line"
    violation=1
  done < "$f"
done < "$filelist"
rm -f "$filelist"
trap - EXIT
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
