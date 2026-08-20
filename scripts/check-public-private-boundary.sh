#!/bin/sh

set -eu

fail=0

self_exclude='scripts/check-public-private-boundary.sh|scripts/test-public-private-boundary-gate.sh|^DECISIONS\.md$'
# DECISIONS.md is excluded deliberately: it is an immutable historical
# log, and it already carries its own header note (added the day this
# gate was written) explaining that its dev/*-2026-08-16.md citations
# are provenance for past decisions, not live links. Every other
# tracked file is still checked in full.

fossh_ls_files() {
  git ls-files -z --cached --others --exclude-standard
}

echo "== public files must never name a private-onlyauthor/ file =="

if [ -d private-onlyauthor ]; then
  tracked_basenames=$(fossh_ls_files | tr '\0' '\n' | grep -vE '^private-onlyauthor/' | xargs -n1 basename 2>/dev/null | sort -u)
  names=$(find private-onlyauthor -type f -exec basename {} \; | sort -u | while IFS= read -r n; do
    printf '%s\n' "$tracked_basenames" | grep -qFx "$n" || printf '%s\n' "$n"
  done)
  if [ -n "$names" ]; then
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      matches=$(fossh_ls_files | grep -zvE "$self_exclude" | grep -zvE '^private-onlyauthor/' | xargs -0 grep -InF "$name" 2>/dev/null || true)
      if [ -n "$matches" ]; then
        echo "$matches"
        echo "FAIL: a tracked, public file names a private-onlyauthor/ file: $name"
        fail=1
      fi
    done <<EOF
$names
EOF
    if [ "$fail" -eq 0 ]; then
      echo "clean ($(printf '%s\n' "$names" | wc -l) private filename(s) checked against every tracked file)"
    fi
  else
    echo "clean (private-onlyauthor/ exists but is empty)"
  fi
else
  echo "SKIPPED: private-onlyauthor/ does not exist on this machine, nothing to check basenames against"
  echo "  run this locally, where private-onlyauthor/ actually exists, before every release/push -- CI checking out a fresh clone can never do this check meaningfully, since the directory is gitignored by design"
fi

echo "== zip build scripts must never draw from an unfiltered file list =="

for script in scripts/build-release-zip.sh scripts/build-documents-zip.sh; do
  if [ -f "$script" ]; then
    if grep -qE 'git .* add -A|git .* add \.' "$script"; then
      echo "FAIL: $script stages the working tree with add -A/add . -- this defeats read-tree HEAD's tracked-only guarantee (the exact bug fixed in fc17b5e)"
      fail=1
    fi
  fi
done
if [ "$fail" -eq 0 ]; then
  echo "clean"
fi

echo
if [ "$fail" -ne 0 ]; then
  echo "public-private-boundary: FAILED"
  exit 1
fi
echo "public-private-boundary: all checks passed"
