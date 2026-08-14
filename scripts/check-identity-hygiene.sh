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

# Real structural gap found and documented during the 2026-08 comprehensive
# pass (dev/DURUM.md's top entry): a plain `git ls-files` only lists
# *tracked* files, so any real leak sitting in a new, not-yet-`git add`ed
# file (routine mid-session, this project generates plenty) sailed through
# every sweep below unseen — the gate only looked clean because it was
# blind to exactly the files most likely to be fresh, unreviewed work.
# `--cached --others --exclude-standard` covers tracked files *and*
# untracked-but-not-gitignored ones (build output, `dist/`, `target/`
# etc. stay excluded via .gitignore, same as before), with no `git add`
# required first — closing the gap at the scan itself, not by asking
# every future run to remember an extra staging step.
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
# No required trailing slash: a real leak (found the hard way, in this
# codebase's own prose — see ADR-0054) can end in punctuation like a
# backtick right after the username, not just another path segment.
# A placeholder like /home/<user> still won't match: '<' breaks the
# character class immediately, same as it did before this fix. No '.'
# in the class either, deliberately: a bare "/home/" or "/Users/"
# mentioned in prose and immediately followed by sentence-ending
# punctuation (e.g. "...grep for /home/ and /Users/. Zero hits.") is
# not a leak, and '.' being a valid (if rare) username character isn't
# worth the false positive — real usernames overwhelmingly don't need
# it, per POSIX's own portable username charset.
# Matched text is captured to a variable and tested with `[ -n ... ]`
# rather than branching on the pipeline's own exit status: xargs
# returns 123 whenever ANY batched grep invocation exits 1-125, and a
# file git still has staged/tracked but that's been deleted from disk
# (an unstaged `rm`, not a `git rm`) makes grep exit 2 on that file —
# indistinguishable, at the exit-status level, from a real match
# existing in a different, earlier batch. Reproduced for real: with
# PRIVACY.tr.md/README.tr.md deleted-but-not-staged, every sweep below
# reported "clean" via the `else` branch regardless of what grep had
# actually matched and printed, because xargs' exit code was 123
# either way. Checking the captured text itself instead of the exit
# status is correct regardless of how many batches xargs uses, and
# regardless of unrelated missing-file errors in other batches.
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
# Two passes over a real temp file, not `for f in $(...)` directly: that
# unquoted-word-splitting form breaks on any tracked filename containing
# a space (splits it into bogus half-paths, then fails the subsequent
# `done < "$f"` redirection outright) — not currently triggered (no such
# filename exists in this tree today) but a real, reproducible gap all
# the same, and the exact "path with spaces" shape this gate's own
# design brief calls out. A plain pipe into `while read` would dodge the
# splitting but silently loses `violation=1` instead — POSIX/dash (and
# bash without `lastpipe`) run the right side of a pipe in a subshell,
# so the assignment would never reach the check below. Redirecting from
# a real file keeps the loop in the current shell.
filelist=$(mktemp)
trap 'rm -f "$filelist"' EXIT
fossh_ls_files | tr '\0' '\n' | grep -E '\.sh$|(^|/)Makefile$|\.github/workflows/.*\.ya?ml$' | grep -vE "$self_exclude" > "$filelist" || true
while IFS= read -r f; do
  [ -n "$f" ] || continue
  line_no=0
  while IFS= read -r line || [ -n "$line" ]; do
    line_no=$((line_no + 1))
    case "$line" in
      *'$0aptile'*) : ;; # contains the literal token somewhere — inspect further
      *) continue ;;
    esac
    # Strip every escaped occurrence first, then re-check: the line is
    # only safe if NO occurrence remains unescaped. A blanket "the
    # escaped form appears somewhere on this line -> safe" (the
    # original form of this check) is a real false negative — a line
    # with both an escaped and a genuinely unquoted occurrence (e.g.
    # `echo "\$0aptile and unquoted $0aptile"`) was reported clean,
    # reproduced and confirmed during this review.
    stripped=$(printf '%s\n' "$line" | sed 's/\\\$0aptile//g')
    case "$stripped" in
      *'$0aptile'*) ;; # a non-escaped occurrence remains — fall through
      *) continue ;; # every occurrence on this line was escaped: safe
    esac
    case "$line" in
      *'"'*) ;; # a double quote is present: single-quote nesting would not actually help — fall through to the failure below
      *"'"'$0aptile'"'"*) continue ;; # single-quoted, and no double quote on the line at all: safe
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
