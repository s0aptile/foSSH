# Upgrading from 0.1.x to 0.2.0

Read `RETIREMENT.md` first for why the 0.1.x line is retired rather
than merely superseded.

There is no in-place upgrade and no migration tool. That is a decision,
not an omission: 0.1.x was an open alpha whose on-disk state was never
promised to be stable, and shipping a migration for state that was
explicitly provisional would be claiming a compatibility guarantee that
was never made.

## What carries over

**Your event data.** The SQLite database (`fossh.db`) and its schema
are unchanged between 0.1.3 and 0.2.0. The rollup tables, the site
records, the write keys and the k-anonymity fold all behave exactly as
before. Copy the data directory and 0.2.0 will read it.

**Your configuration.** `fossh.toml` is unchanged. Every key it
accepted in 0.1.3 it still accepts, with the same meanings.

**Your integrations with other software.** The CGI and FastCGI
endpoints, the C ABI in `libfossh`, and the PHP/Go/Ruby bindings are
all wire-compatible. Nothing that sends events to foSSH needs to
change.

## What does not carry over

**`fossh-tui` is gone.** There is no terminal console in 0.2.0. If you
had it in a script, a systemd unit, or a habit, the replacements are
`fossh-console` (a desktop application) and the `fossh` CLI, which is
unchanged.

**Operator enrollment may need redoing.** If you enrolled an operator
key against a 0.1.x watchdog, that enrollment is still valid — the key
material and the pinning are unchanged. But if you *thought* you had
enrolled one through the 0.1.x setup wizard before it was connected to
the real protocol (see `RETIREMENT.md`), you did not, and the console
will show you a setup token still waiting. That is not a regression;
it is the first accurate report you have had.

## The upgrade

Nothing here needs the service to be reinstalled from scratch; the
package upgrade path works. These steps are what to do around it.

**1. Stop the services.**

```
sudo systemctl stop fossh-watchdog fossh-fcgi
```

**2. Back up the data directory.** Not optional. This is the only step
that is hard to undo if skipped.

```
sudo tar czf ~/fossh-data-backup-$(date +%F).tar.gz -C /var/lib fossh
```

**3. Upgrade the package.**

```
sudo dnf upgrade fossh fossh-watchdog fossh-console
```

On Fedora Atomic (Silverblue, Kinoite, CoreOS):

```
rpm-ostree upgrade
systemctl reboot
```

**4. Check what the install thinks of itself.** `fossh doctor` runs the
same deterministic self-healing rules the console shows, and will name
anything the upgrade left in an odd state.

```
sudo fossh doctor
```

**5. Start the services and open the console.**

```
sudo systemctl start fossh-watchdog fossh-fcgi
fossh-console
```

## If you would rather start clean

Reasonable, given the above. Keep your database, discard everything
else:

```
sudo systemctl stop fossh-watchdog fossh-fcgi
sudo cp /var/lib/fossh/fossh.db ~/fossh.db.keep
sudo dnf remove fossh fossh-watchdog
sudo rm -rf /var/lib/fossh /var/lib/fossh-watchdog /etc/fossh
sudo dnf install fossh fossh-watchdog fossh-console
sudo fossh init --dir /var/lib/fossh
sudo systemctl stop fossh-fcgi
sudo cp ~/fossh.db.keep /var/lib/fossh/fossh.db
sudo chown fossh-svc:fossh-svc /var/lib/fossh/fossh.db
sudo systemctl start fossh-fcgi
```

One caveat worth stating: a fresh `fossh init` generates a **new data
key**, and the restored database was encrypted under the old one. If
you take this path, restore `.data_key` alongside `fossh.db` or the
store will not open. Anything sealed under the old key that you do not
restore — the spool, stored integration credentials — is not
recoverable, which is the point of sealing it.
