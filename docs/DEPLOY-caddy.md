# Deploying foSSH under Caddy

Caddy doesn't speak plain CGI natively — like nginx, it needs `fcgiwrap` to bridge FastCGI to a per-request CGI exec of `fossh-cgi`. See `docs/preview/DEPLOY-nginx-cloudflare-tunnel.md` §2 for the `fcgiwrap` systemd units this project ships (`packaging/systemd/fossh-fcgiwrap.{socket,service}`) — those units themselves are the same reviewed §3.2 packaging either way; the setup below assumes they're already installed and running, and covers only the Caddy-specific side.

## 1. Install and start `fcgiwrap`

```
sudo dnf install fcgiwrap   # or your distro's equivalent
sudo cp packaging/systemd/fossh-fcgiwrap.socket packaging/systemd/fossh-fcgiwrap.service /etc/systemd/system/
sudo cp packaging/systemd/fossh.tmpfiles.conf /usr/lib/tmpfiles.d/fossh.conf
sudo systemd-tmpfiles --create
sudo systemctl enable --now fossh-fcgiwrap.socket
```

## 2. Caddyfile

```caddyfile
your-site.example {
    @fossh path /e /e.gif
    reverse_proxy @fossh unix//run/fossh/fcgiwrap.sock {
        transport fastcgi {
            root /usr/bin
            split_fossh-cgi
            env SCRIPT_FILENAME /usr/bin/fossh-cgi
        }
    }

    respond @fossh 404 {
        # unreachable — the reverse_proxy above always handles @fossh first;
        # kept only so `@fossh` reads as an exhaustive match in this block
    }
}
```

Caddy's `fastcgi` transport needs `SCRIPT_FILENAME` set explicitly (shown above) since there's no on-disk PHP-style script for it to infer the path from — `fossh-cgi` is a compiled binary, not an interpreted script, and this is exactly the same `SCRIPT_FILENAME` value the nginx config passes for the same reason.

## 3. `X-Forwarded-For` — read this before relying on visitor counts

If Caddy itself is directly internet-facing (not behind another proxy like Cloudflare Tunnel), `fcgiwrap`/`fossh-cgi` already sees the real visitor's IP as `REMOTE_ADDR` with no extra configuration — Caddy sets that correctly by default. `FOSSH_TRUST_FORWARDED_FOR` (in `fossh-fcgiwrap.service`'s `Environment=`) is only relevant if Caddy itself sits behind another reverse proxy or tunnel; see `docs/preview/DEPLOY-nginx-cloudflare-tunnel.md`'s note on this same setting for the reasoning — it applies identically here.

## 4. `fossh maintain` via cron or a timer

```
sudo crontab -e
```

```cron
* * * * * FOSSH_CONFIG=/etc/fossh/fossh.toml /usr/bin/fossh maintain >> /var/log/fossh-maintain.log 2>&1
```

Or a `systemd` timer if you'd rather not use cron — either works; nothing about `fossh maintain` depends on which scheduler invokes it.

## 5. Verify

```
curl -i "https://your-site.example/e.gif?name=pageview" -H "Authorization: Bearer <your-write-key>"
fossh query --site my-site --from $(date +%F) --to $(date +%F) --metric hits,uniques
```
