#!/bin/bash

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

  if [ "$1" -eq 0 ]; then
    echo "ok:   $2"
  else
    echo "FAIL: $2"
    fail=1
  fi
}

install -d -m0700 -o fossh-svc -g fossh-svc /var/lib/fossh
install -d -m0700 -o fossh-watchdog -g fossh-watchdog /var/lib/fossh-watchdog

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

if runuser -u fossh-watchdog -- test -r /var/lib/fossh-watchdog/secret.txt 2>/dev/null; then
  check 0 "fossh-watchdog can read its own secret file (sanity check)"
else
  check 1 "fossh-watchdog can read its own secret file (sanity check)"
fi

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
