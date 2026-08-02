# Deploying foSSH under Apache (`mod_cgi`)

## 1. Install the binary and initialize a data directory

```
sudo install -D -m0755 target/release/fossh-cgi /usr/lib/cgi-bin/fossh-cgi
sudo mkdir -p /var/lib/fossh /run/fossh
sudo fossh init --dir /var/lib/fossh
sudo fossh site create my-site --allow pageview,signup
```

Note the write key that prints — it's shown once.

## 2. File permissions

```
sudo chown -R www-data:www-data /var/lib/fossh /run/fossh   # or apache:apache on RHEL/Fedora
sudo chmod 0700 /var/lib/fossh /run/fossh
```

`fossh doctor` (run as the same user Apache runs as) verifies this and fails loudly if a permission has drifted wider than expected — run it after any manual change.

## 3. Apache config

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
</Location>
<Location "/e.gif">
    SetHandler cgi-script
    SetEnv FOSSH_DATA_DIR /var/lib/fossh
    SetEnv FOSSH_SALT_DIR /run/fossh
</Location>

ScriptAlias /e /usr/lib/cgi-bin/fossh-cgi
ScriptAlias /e.gif /usr/lib/cgi-bin/fossh-cgi
```

`mod_cgi` runs as whatever user Apache itself runs as (`www-data`, `apache`, or similar) — there's no separate privilege-drop step needed here the way the Fedora-native systemd unit has one, since Apache never runs `mod_cgi` scripts as root to begin with in a normal install. `fossh-cgi`'s own privilege-drop code (§3.2) still applies defensively if it somehow is invoked as root.

## 4. `fossh maintain` via cron

`fossh-cgi` only ever spools events (in `mode = "spool"`, the default) — something needs to periodically drain the spool into the database, enforce retention, and vacuum:

```
sudo crontab -u www-data -e
```

```cron
* * * * * FOSSH_CONFIG=/etc/fossh/fossh.toml /usr/local/bin/fossh maintain >> /var/log/fossh-maintain.log 2>&1
```

Every minute is a reasonable default — `fossh maintain` is idempotent and cheap when there's nothing to drain.

## 5. Verify

```
curl -i "http://your-site/e.gif?name=pageview" -H "Authorization: Bearer <your-write-key>"
fossh query --site my-site --from $(date +%F) --to $(date +%F) --metric hits,uniques
```
