#!/bin/bash
# §3.5: real filesystem-permission verification that fossh-svc (core)
# and fossh-watchdog cannot reach into each other's own data — "actual
# filesystem tests, not just design docs" (prrr.md §3.5). Must run as
# root: it creates/chowns real system paths (packaging/rpm/fossh.spec
# creates and owns /var/lib/fossh itself during a real package
# install, but does not yet create /var/lib/fossh-watchdog — no
# systemd unit/packaging exists for the watchdog yet, a separate,
# already-tracked gap — so this script creates both directories
# itself, matching §2.3's model exactly: each service owns one
# directory, mode 0700, the other service has no access to it at
# all), then drops to each service user via `runuser` (not `su` —
# works against /sbin/nologin accounts without needing a real login
# shell or PAM session, which is exactly what a service account like
# this needs) to test enforcement directly, not assume it.
#
# Leaves both directories in place afterward (they are the real
# production paths these services need to exist anyway); only removes
# this script's own test file.
#
# Usage: sudo bash scripts/verify-privilege-separation.sh

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "must run as root (creates/chowns real system paths): sudo bash $0" >&2
  exit 1
fi

for user in fossh-svc fossh-watchdog; do
  if ! id "$user" >/dev/null 2>&1; then
    echo "missing system user: $user — see packaging/rpm/fossh.spec's own useradd invocations" >&2
    exit 1
  fi
done

fail=0
check() {
  # $1: 0 if the check passed, nonzero if it failed. $2: description.
  if [ "$1" -eq 0 ]; then
    echo "ok:   $2"
  else
    echo "FAIL: $2"
    fail=1
  fi
}

install -d -m0700 -o fossh-svc -g fossh-svc /var/lib/fossh
install -d -m0700 -o fossh-watchdog -g fossh-watchdog /var/lib/fossh-watchdog

# Stands in for a real watchdog secret (its OpenPGP keypair, TLS
# identity, or a pin file) — the actual file identity doesn't matter,
# only that it is fossh-watchdog's own, mode 0600.
echo "stand-in for a real fossh-watchdog secret" >/var/lib/fossh-watchdog/secret.txt
chown fossh-watchdog:fossh-watchdog /var/lib/fossh-watchdog/secret.txt
chmod 0600 /var/lib/fossh-watchdog/secret.txt

echo "=== §3.5: privilege separation between fossh-svc and fossh-watchdog ==="

if runuser -u fossh-svc -- test -r /var/lib/fossh-watchdog/secret.txt 2>/dev/null; then
  check 1 "fossh-svc cannot read fossh-watchdog's secret file"
else
  check 0 "fossh-svc cannot read fossh-watchdog's secret file"
fi

if runuser -u fossh-svc -- ls /var/lib/fossh-watchdog >/dev/null 2>&1; then
  check 1 "fossh-svc cannot list fossh-watchdog's directory"
else
  check 0 "fossh-svc cannot list fossh-watchdog's directory"
fi

if runuser -u fossh-svc -- sh -c 'echo x > /var/lib/fossh-watchdog/attempted-write' 2>/dev/null; then
  check 1 "fossh-svc cannot create a new file inside fossh-watchdog's directory"
  rm -f /var/lib/fossh-watchdog/attempted-write
else
  check 0 "fossh-svc cannot create a new file inside fossh-watchdog's directory"
fi

if runuser -u fossh-svc -- sh -c 'echo x > /var/lib/fossh-watchdog/secret.txt' 2>/dev/null; then
  check 1 "fossh-svc cannot overwrite fossh-watchdog's existing secret file"
else
  check 0 "fossh-svc cannot overwrite fossh-watchdog's existing secret file"
fi

# Sanity check, the other direction: fossh-watchdog CAN reach its own
# file. Proves the checks above are failing for the right reason
# (real permission enforcement), not because the path is broken or
# unreadable to everyone including its own owner.
if runuser -u fossh-watchdog -- test -r /var/lib/fossh-watchdog/secret.txt 2>/dev/null; then
  check 0 "fossh-watchdog can read its own secret file (sanity check)"
else
  check 1 "fossh-watchdog can read its own secret file (sanity check)"
fi

# The boundary is meant to hold both directions — prrr.md §3.5's own
# wording is one-directional (fossh-svc must not reach
# fossh-watchdog's files), but a watchdog able to freely rewrite
# core's own data directory would be a real, separate privilege gap,
# so this is checked too rather than assumed fine by omission.
if runuser -u fossh-watchdog -- sh -c 'echo x > /var/lib/fossh/attempted-write' 2>/dev/null; then
  check 1 "fossh-watchdog cannot write into fossh-svc's own directory"
  rm -f /var/lib/fossh/attempted-write
else
  check 0 "fossh-watchdog cannot write into fossh-svc's own directory"
fi

rm -f /var/lib/fossh-watchdog/secret.txt

echo
if [ "$fail" -eq 0 ]; then
  echo "All privilege-separation checks passed."
else
  echo "One or more privilege-separation checks FAILED — see above."
fi
exit "$fail"
