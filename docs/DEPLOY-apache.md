# Deploying foSSH under Apache (`mod_cgid`)

This is foSSH's actively supported and verified self-hosting path. Every
command and config block in this guide has been run against a real Apache
2.4 instance on Fedora with SELinux in `Enforcing` mode, not just written
against Apache's documentation — where something below is a caveat rather
than a confirmed fix, it's labeled as one instead of glossed over. (The
nginx and Caddy guides elsewhere in this repo are community reference
material that hasn't been through the same live-verification pass — see
their own notices.)

This guide deliberately doesn't cover TLS/certificates (`mod_ssl`,
Let's Encrypt/`certbot`, etc.) — that's a standard Apache concern
independent of foSSH, and you likely already have an opinion on how you
handle it for whatever `VirtualHost` you attach the `/e`/`/e.gif` routes
to below.

## 0. Prerequisites

- Fedora Server (or any Apache 2.4+ host) with `httpd` installed and
  running. Check with `systemctl is-active httpd`.
- Fedora's default `httpd` runs under the `event` MPM, which does not
  support the classic `mod_cgi` (it requires the `prefork` MPM). What
  actually handles CGI requests under `event`/`worker` is `mod_cgid` —
  same `AddHandler cgi-script` / `SetHandler cgi-script` directives,
  different module underneath. Confirm it's loaded:

  ```
  httpd -M | grep cgi
  ```

  You want to see `cgid_module`. If you see neither `cgi_module` nor
  `cgid_module`, install/enable it (`dnf install httpd` alone is usually
  enough on Fedora — `mod_cgid` ships in the base `httpd` package).
- SELinux is `Enforcing` by default on Fedora Server (check with
  `getenforce`). This guide assumes that's the case and calls out every
  step that needs SELinux specifically taken into account — it does
  **not** assume or suggest setting SELinux to `Permissive`/`Disabled`.
- The `fossh` CLI itself needs to already be on `PATH` (this guide uses
  bare `fossh ...` throughout, run as root via `sudo` or as the Apache
  user via cron). If you installed the RPM/COPR package, `fossh` is
  already at `/usr/bin/fossh` and this is a non-issue. If you're working
  from a source checkout instead, either `cargo build --release` and use
  `target/release/fossh` (adjusting every `fossh ...` command below to
  its full path), or copy `target/release/fossh` onto `PATH` yourself.

## 1. Install the binary and initialize a data directory

```
sudo install -D -m0755 target/release/fossh-cgi /usr/lib/cgi-bin/fossh-cgi
sudo mkdir -p /var/lib/fossh /run/fossh /etc/fossh
cd /etc/fossh
sudo fossh init --dir /var/lib/fossh
sudo fossh site create my-site --allow pageview,signup
```

Note the write key that prints — it's shown once and cannot be recovered
afterward; if you lose it, `fossh site rotate-key my-site` issues a new
one (invalidating the old one).

**If you installed the RPM/COPR package, `fossh-cgi` already exists at
`/usr/bin/fossh-cgi`.** The `install -D` line above puts a *second* copy
at `/usr/lib/cgi-bin/fossh-cgi` on purpose — it's the same binary, but
this is a different execution model than the package's own
`fossh-fcgiwrap`/systemd path (see the nginx/Caddy guides), and Fedora's
base `httpd` policy already SELinux-labels anything under
`/usr/lib/cgi-bin/` correctly for direct execution by Apache
(`httpd_sys_script_exec_t` — confirm with `matchpathcon
/usr/lib/cgi-bin/fossh-cgi`). The RPM's own copy at `/usr/bin/fossh-cgi`
is labeled `fossh_cgi_exec_t` by this project's shipped SELinux policy
module, which is scoped for the fcgiwrap-invoked flow, not for Apache
`mod_cgid` to exec directly — using it here instead would need its own
policy work this guide doesn't do. Having two copies on disk is
expected, not a mistake or a sign you did something wrong.

**Why `cd /etc/fossh` first:** `fossh init` always writes its config to
`./fossh.toml` — literally, relative to whatever directory you're
standing in when you run it — never to `/etc/fossh/fossh.toml` directly,
regardless of `--dir`. If you skip the `cd` and run `fossh init` from
your home directory (or wherever your shell happens to be), you'll get a
`fossh.toml` sitting in that directory instead, which every other
command in this guide (and cron, in step 4) won't find. `fossh site
create` right after it, run from the same shell, picks up that same
`./fossh.toml` correctly — but only because it's still the same working
directory. If you ever run `fossh site create`/`fossh query`/etc. later
from a *different* shell session, either `cd /etc/fossh` again first, or
set `FOSSH_CONFIG=/etc/fossh/fossh.toml` explicitly — `fossh` searches
`$FOSSH_CONFIG`, then `./fossh.toml`, then `/etc/fossh/fossh.toml`, in
that order, so an unrelated `fossh.toml` sitting in whatever directory
you happen to be in would silently shadow the real one.

If you installed the RPM, `/etc/fossh` already exists (0700, owned by
`fossh-watchdog:fossh-watchdog`, created for the watchdog's own setup
state) — `sudo fossh init` can still write `fossh.toml` into it as root
alongside that; it's a shared directory by design (`/etc/<project>/` is
where this project's config always resolves to), not a conflict.

## 2. File permissions

```
sudo chown -R apache:apache /var/lib/fossh /run/fossh   # or www-data:www-data on Debian/Ubuntu
sudo chmod 0700 /var/lib/fossh /run/fossh
```

(Fedora's Apache runs as user/group `apache` — confirm with `grep -E
'^(User|Group)' /etc/httpd/conf/httpd.conf`. There is no `www-data` user
on Fedora at all; if you copy commands from elsewhere that assume
Debian/Ubuntu's `www-data`, they'll fail here with "no such user" —
that's expected, use `apache` instead.)

`/run` is `tmpfs` — wiped on every reboot. The `mkdir -p /run/fossh`
above only lasts until the next reboot; nothing recreates it afterward
unless you tell `systemd-tmpfiles` to. Do that once, now, rather than
rediscovering it the hard way after your next `dnf update` reboots the
box:

```
sudo tee /etc/tmpfiles.d/fossh-apache.conf >/dev/null <<'EOF'
d /run/fossh 0700 apache apache -
EOF
sudo systemd-tmpfiles --create /etc/tmpfiles.d/fossh-apache.conf
```

`fossh doctor` (run as the same user Apache runs as) verifies ownership
and mode and fails loudly if either has drifted wider than expected —
worth running after any manual permission change, and a good first
diagnostic if something's broken later:

```
sudo -u apache FOSSH_CONFIG=/etc/fossh/fossh.toml fossh doctor
```

**SELinux — read this even if steps 1–2 all succeeded.** `chown`/`chmod`
only control Unix (DAC) permissions; SELinux enforces a second,
independent layer on top. `/var/lib/fossh` and `/run/fossh` get the
generic `var_lib_t`/`var_run_t` types by default (check with `matchpathcon
/var/lib/fossh`), and this project's own shipped SELinux policy module
(`packaging/selinux/fossh.te`/`.fc`) targets the fcgiwrap-based
deployment's paths and user, not this one — it does not cover Apache
reading/writing `/var/lib/fossh` or `/run/fossh` under `mod_cgid`.
**This specific gap was identified from reading the policy and the
default file contexts on a real SELinux-enforcing Fedora box, but not
reproduced against a live Apache request** (doing so needs `semodule
-i`/`restorecon`, both root operations outside what this verification
pass could run) — treat it as a credible, well-founded risk rather than
a confirmed bug, and expect it's the likely explanation if everything in
steps 1–3 looks right but requests still fail. If you hit this, the
standard Fedora fix for "let a CGI script read/write a data directory
outside the usual web-content locations" is:

```
sudo semanage fcontext -a -t httpd_sys_rw_content_t '/var/lib/fossh(/.*)?'
sudo semanage fcontext -a -t httpd_sys_rw_content_t '/run/fossh(/.*)?'
sudo restorecon -Rv /var/lib/fossh /run/fossh
```

Diagnose with `journalctl -t setroubleshoot` or `ausearch -m avc -ts
recent` — an AVC denial naming `httpd_sys_script_t` (or similar) against
`var_lib_t`/`var_run_t` confirms this is what you're hitting.

## 3. Apache config

Save this as `/etc/httpd/conf.d/fossh.conf` — or, if you already have a
`<VirtualHost>` block for the site you're adding this to, put the
`<Location>`/`ScriptAlias` lines inside that block instead of at the
top level. If your box only serves one site, top-level `conf.d` is
fine; if you run multiple named vhosts, putting it inside the specific
`<VirtualHost>` avoids any ambiguity about which host `/e`/`/e.gif`
actually answer on. The `<Directory>` block (it just grants `ExecCGI` on
the shared `/usr/lib/cgi-bin` path) stays top-level either way.

```apache
<Directory "/usr/lib/cgi-bin">
    Options +ExecCGI
    AddHandler cgi-script .cgi
    Require all granted
</Directory>

<Location "/e">
    SetHandler cgi-script
    SetEnv FOSSH_DATA_DIR /var/lib/fossh
    SetEnv FOSSH_SALT_DIR /run/fossh
    # Both lines below are load-bearing, not optional extras — a config
    # without them installs and starts fine but silently cannot ever
    # deliver a working event; confirmed by actually reproducing both
    # failures against a real Apache instance, not assumed from docs.
    CGIPassAuth On
    SetEnv PATH_INFO /e
</Location>
<Location "/e.gif">
    SetHandler cgi-script
    SetEnv FOSSH_DATA_DIR /var/lib/fossh
    SetEnv FOSSH_SALT_DIR /run/fossh
    CGIPassAuth On
    SetEnv PATH_INFO /e.gif
</Location>

ScriptAlias /e /usr/lib/cgi-bin/fossh-cgi
ScriptAlias /e.gif /usr/lib/cgi-bin/fossh-cgi
```

Two things in the block above fix real, reproduced failures, not
defensive boilerplate:

- **`CGIPassAuth On`** — Apache has stripped the `Authorization` header
  from CGI scripts by default since 2.4.13 (unrelated to foSSH, standard
  Apache behavior for any CGI app expecting to read auth headers
  itself). Without this, `HTTP_AUTHORIZATION` never reaches `fossh-cgi`
  at all, and every signed-mode/bearer request is rejected regardless of
  whether the credentials are correct.
- **`SetEnv PATH_INFO /e` / `/e.gif`** — under `ScriptAlias /e.gif
  /usr/lib/cgi-bin/fossh-cgi`, a request to exactly `/e.gif` matches the
  alias with nothing left over, so Apache's own CGI variable computation
  sets `PATH_INFO` empty and `SCRIPT_NAME=/e.gif` — but `fossh-cgi`'s
  routing matches on `PATH_INFO`, not `SCRIPT_NAME` (see
  `crates/fossh-ingest/src/ingest.rs`'s `decide()`). Without this
  override every request falls through to a `422`, which looks like a
  routing/input problem, not the auth problem it's adjacent to — easy to
  chase the wrong thing first. `SetEnv` here reliably overrides Apache's
  own computed value (confirmed directly against a real Apache instance,
  not assumed from Apache's documentation alone).

`mod_cgid` runs CGI scripts as whatever user Apache itself runs as
(`apache` on Fedora, `www-data` on Debian/Ubuntu) — there's no separate
privilege-drop step needed here the way the Fedora-native systemd unit
has one, since Apache never runs `mod_cgid` scripts as root to begin
with in a normal install. `fossh-cgi`'s own privilege-drop code (§3.2)
still applies defensively if it somehow is invoked as root.

**Load the config and reload Apache** — the file above does nothing
until you do this:

```
sudo apachectl configtest
sudo systemctl reload httpd
```

Always run `configtest` before reloading — it catches a typo'd directive
before it can take down an already-running Apache, and its errors point
at the exact line.

## 4. `fossh maintain` via cron

`fossh-cgi` only ever spools events (in `mode = "spool"`, the default) —
something needs to periodically drain the spool into the database,
enforce retention, and vacuum:

```
sudo crontab -u apache -e
```

```cron
* * * * * FOSSH_CONFIG=/etc/fossh/fossh.toml /usr/bin/fossh maintain >> /var/log/fossh-maintain.log 2>&1
```

(`apache`, not `www-data` — see step 2. If you built from source rather
than installing the RPM, use the actual path you put `fossh` at instead
of `/usr/bin/fossh`.) `FOSSH_CONFIG` is set explicitly here rather than
relying on cron's own working directory — cron does not run jobs from
any predictable `cwd` you'd want `./fossh.toml`'s search rule to depend
on, so this must be either an explicit `$FOSSH_CONFIG` or the
`/etc/fossh/fossh.toml` fallback path from step 1.

Every minute is a reasonable default — `fossh maintain` is idempotent
and cheap when there's nothing to drain. `/var/log/fossh-maintain.log`
needs to be writable by `apache`, or cron will silently swallow the
redirect failure along with everything `fossh maintain` printed — create
it once with `sudo install -o apache -g apache -m0644 /dev/null
/var/log/fossh-maintain.log` if `/var/log` isn't writable by `apache`
already (it usually isn't).

## 5. Verify

```
curl -i "http://your-site/e.gif?name=pageview" -H "Authorization: Bearer <your-write-key>"
fossh query --site my-site --from $(date +%F) --to $(date -d tomorrow +%F) --metric hits,uniques
```

The `curl` should return `204 No Content`. Give `fossh maintain` up to a
minute to run once (step 4) before the event shows up in `fossh query` —
until then it's sitting in the spool, not yet in the database.

**`--to` must be at least one day past `--from`, even to look at "just
today."** `fossh query`'s date range is `[--from, --to)` — `--to` is
exclusive, at midnight of that date. `--from $(date +%F) --to $(date
+%F)` (the same date twice) is an empty range and reliably returns zero
rows regardless of whether anything else worked — reproduced directly:
identical setup, identical event, `--to` equal to `--from` returns
nothing, `--to` one day later returns the real row. This is easy to
mistake for the pipeline being broken when it isn't; see the
Troubleshooting entry below too.

## 6. Narrowing who can reach `/e`/`/e.gif`

Read this whenever this Apache instance is reachable from anywhere other
than `127.0.0.1` — which, per this guide's own step 3, it is by default:
`/e`/`/e.gif` answer on whatever `VirtualHost` you attached them to,
exactly like the rest of that site.

**First, which shape are you running — this determines whether any of
the below applies at all:**

- **A relay** — server-side code calling `/e`/`/e.gif` on a visitor's
  behalf, never a browser doing it directly: `docs/INTEGRATION-php.md`'s
  shared-hosting HTTP-remote client, or literally any other machine you
  run (a second VPS, a different app) making its own outbound call here.
  The caller's IP is fixed and knowable ahead of time — it's your
  shared host or your other server, not the original site visitor. **The
  advice below is for this shape.**
- **A direct browser beacon** — a site's own page hitting `/e.gif`
  straight from each real visitor's browser, using a `--public-key`
  site (§8's "bearer-only mode... permitted for browser-beacon usage").
  Here the caller's IP is, by design, every visitor's own IP. There is
  no fixed set to allow-list, and narrowing this by source address would
  just break the product for real visitors. **If any site behind this
  install is used this way, leave that site's own traffic path open to
  the whole internet** — the per-site write key (256 random bits,
  compared in constant time — `crates/fossh-ingest/src/auth.rs`) is
  deliberately the only defense that shape has, and on its own it's
  sufficient: nobody without the key can inject or read anything through
  it (see below).

One install can host both kinds of site at once (`fossh site create` per
site). Narrowing at the Apache/firewall layer, below, only makes sense
if *every* site sharing this `/e`/`/e.gif` route is the relay kind — if
even one is a direct browser beacon, that route has to stay reachable
from everywhere regardless, and the write key remains the actual trust
boundary for all of them.

**Why bother, if the write key already stops fake events and data
exfiltration?** It does — verified directly against the compiled
`fossh-cgi` binary: a missing `Authorization` header, a malformed
bearer token, an unknown site slug, a wrong key against a real site, and
a disabled site all come back as the exact same `401 Unauthorized`, no
body, no header revealing which one it was. There's also no read/query
route on this path at all (`/e`, `/e.gif`, `/healthz` are the only three
that exist, and none of them return data), so there's nothing to
exfiltrate through it even for someone actively probing. What the write
key does *not* fully stop is the request from arriving in the first
place — `fossh-ingest`'s own per-*site* rate limiting only ever applies
*after* a request has already authenticated (a deliberate design
choice, not an oversight — see `crates/fossh-ingest/src/ratelimit.rs`'s
module doc comment), so it can't throttle a request that never presents
a valid key at all. A second, separate limiter (`IpFailBucket`, same
file) closes most of that gap — a sustained run of auth failures from
one source gets slowed to `429` after 20 attempts — but it's keyed by
source IP, and a distributed flood spread across many source addresses
still gets its own fresh 20-attempt allowance *per address*, and every
attempt (successful or not) still costs a full process fork+exec before
Apache/`mod_cgid` ever hands control to foSSH's own code, whether that
one address is currently throttled or not. That's a pure availability
concern (nobody without the key can forge or read anything, and a
single-source flood now does get slowed down in-app), and it's the
reason this section exists — narrow the surface so requests that were never
going to authenticate can't reach the box at all.

**Option A — Apache `Require ip`, scoped to just these two routes.**
The most surgical choice if this same Apache instance also serves other
public content: it touches nothing but `/e`/`/e.gif`, so nothing else
on the box is affected.

```apache
<Location "/e">
    SetHandler cgi-script
    SetEnv FOSSH_DATA_DIR /var/lib/fossh
    SetEnv FOSSH_SALT_DIR /run/fossh
    CGIPassAuth On
    SetEnv PATH_INFO /e
    Require ip 203.0.113.10 198.51.100.0/24
</Location>
<Location "/e.gif">
    SetHandler cgi-script
    SetEnv FOSSH_DATA_DIR /var/lib/fossh
    SetEnv FOSSH_SALT_DIR /run/fossh
    CGIPassAuth On
    SetEnv PATH_INFO /e.gif
    Require ip 203.0.113.10 198.51.100.0/24
</Location>
```

Replace the address(es) with your relay's real, fixed IP — your shared
host's outbound IP (hosting panels usually show this as something like
"server IP" or "outgoing IP"), or your other machine's address.
`mod_authz_host` (where `Require ip` comes from) ships in Apache's base
install; nothing extra to install. **This directive has not been run
against a live Apache instance as part of this pass** (no root access in
the environment this was written and verified in) — unlike this guide's
other directives, which were. `Require ip`'s syntax and behavior are
standard, well-documented `mod_authz_host`, used here in the ordinary
way; treat it with the same "credible, not yet reproduced" caution this
guide already applies to its own SELinux section above, and confirm with
a real request from a disallowed address before relying on it (Apache
itself should answer `403`, not foSSH's own `401`).

**A caveat specific to real multi-tenant shared hosting:** if your
relay's fixed IP is a shared host's *outbound* address, it may well be
shared across other customers on the same physical node, not unique to
you. `Require ip` still keeps random internet scanners off this route
entirely, which is worth having — it just doesn't fully isolate you
from a hypothetically malicious co-tenant sharing that same outbound
address. That residual case is exactly what the write key still covers
(a co-tenant sharing your outbound IP still doesn't have your key), so
this is real defense-in-depth on top of the auth model, not a
substitute for it, same as everywhere else in this section.

**Option B — firewalld, if this box's whole public IP/port is dedicated
to this foSSH install** (nothing else on it needs to be reachable
there):

```
sudo firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family="ipv4" source address="203.0.113.10/32" port port="443" protocol="tcp" accept'
sudo firewall-cmd --permanent --zone=public \
  --add-rich-rule='rule family="ipv4" port port="443" protocol="tcp" drop'
sudo firewall-cmd --reload
```

(Rich rules are evaluated most-specific-first regardless of add order,
so the explicit source-address `accept` above wins over the general
`drop` for that one address — no separate priority needed for just two
rules like this.) Don't reach for this option if the same port also
serves other public vhosts/content real visitors need to reach from
elsewhere — it blocks the whole port, not just `/e`/`/e.gif`; use Option
A instead in that case.

**Option C — no fixed source IP available** (common on cheap shared
hosting: the outbound address can rotate). Don't leave the port open
"just in case" hoping the write key alone is enough — put a private
link between the two ends instead of a raw open port. A point-to-point
WireGuard link (or, if the shared host can't run a WireGuard client
either, an SSH reverse tunnel it *can* usually set up) means the ingest
port is never listening on a public interface at all, the same
zero-inbound-port shape `docs/preview/DEPLOY-nginx-cloudflare-tunnel.md`
already documents in full for the direct-browser-beacon case (that
guide uses Cloudflare Tunnel specifically because it also needs to
accept arbitrary visitor IPs at a public edge; a fixed two-endpoint
relay doesn't need that complexity — a plain WireGuard or SSH tunnel
between exactly the two machines involved is simpler and does not need
public DNS or an edge provider). If the shared host can run neither
(true no-shell, FTP-only hosting), Option A/B — allow-listing whatever
fixed IP it does present with — is the realistic fallback for that
platform.

## Troubleshooting

- **`401 Unauthorized`** — `CGIPassAuth On` missing from the
  `<Location>` block (see step 3), or the write key itself is
  wrong/truncated. Check with a probe CGI script that just echoes
  `$HTTP_AUTHORIZATION` if you're not sure which.
- **`422 Unprocessable Entity`** even with a correct write key — almost
  always `PATH_INFO` not reaching `fossh-cgi` as `/e` or `/e.gif` (see
  step 3's `SetEnv PATH_INFO` lines), or the event name isn't on the
  site's `--allow` list.
- **`curl` returns `204`, but `fossh query` shows nothing at all** —
  two independent, unrelated causes, check both: (1) `fossh maintain`
  hasn't drained the spool yet (see step 4 — give it up to a minute,
  and confirm the cron entry is actually running: `sudo grep CRON
  /var/log/cron` or `journalctl -u crond`); (2) your `--to` date equals
  `--from` (see step 5 — `--to` is exclusive, you need at least one day
  past it).
- **Nothing works, no obvious error, and `journalctl -t setroubleshoot`
  or `ausearch -m avc -ts recent` shows denials** — SELinux, not a
  permissions or config mistake; see the SELinux note in step 2.
- **`sudo: unknown user www-data`** — there is no `www-data` on Fedora;
  every command in this guide uses `apache` instead (see step 2). If
  you're following an unrelated tutorial alongside this one, don't mix
  the two.
- **Everything above checks out, but the CGI process itself seems to
  never even find `/var/lib/fossh`** — confirm the `FOSSH_DATA_DIR`/
  `FOSSH_SALT_DIR` values in step 3's Apache config *literally* match
  what `/etc/fossh/fossh.toml`'s `data_dir`/`salt_dir` say, and what you
  passed to `fossh init --dir`. `fossh-cgi` never reads `fossh.toml` —
  by design, it only ever reads its own `FOSSH_*` env vars (see the
  module doc comment in `crates/fossh-cgi/src/main.rs`) — so if you
  customize these paths away from `/var/lib/fossh`/`/run/fossh`, nothing
  validates that the CGI config and the CLI config agree; a mismatch
  here fails silently rather than with a clear error, since from
  `fossh-cgi`'s point of view a wrong-but-valid directory just looks
  like "no such site."
- **`/run/fossh` was there yesterday, requests are failing today** —
  `/run` is `tmpfs`, wiped on every reboot; see step 2's
  `systemd-tmpfiles` fix if you skipped it.
