# Deploying foSSH under Caddy

> **Community reference, not this project's verified path.** foSSH's
> actively supported and live-verified deployment path is
> [Apache](DEPLOY-apache.md) — every command and config block there has
> been run against a real Apache instance. This Caddy guide is provided
> as a starting point for anyone already committed to Caddy; the
> Caddy-specific config below is written correctly to the best of this
> project's understanding of Caddy's own documented behavior, but it has
> not been run against a real Caddy instance, and isn't receiving the
> same ongoing verification effort Apache is. If you can run Apache
> instead, do that.

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
            env SCRIPT_FILENAME /usr/bin/fossh-cgi
            env PATH_INFO {http.request.uri.path}
        }
    }

    respond @fossh 404 {
        # unreachable — the reverse_proxy above always handles @fossh first;
        # kept only so `@fossh` reads as an exhaustive match in this block
    }
}
```

Caddy's `fastcgi` transport needs `SCRIPT_FILENAME` set explicitly (shown above) since there's no on-disk PHP-style script for it to infer the path from — `fossh-cgi` is a compiled binary, not an interpreted script, and this is exactly the same `SCRIPT_FILENAME` value the nginx config passes for the same reason.

**Two corrections to this block, found during a final review pass:** the previous version of this guide had a `split_fossh-cgi` line, which is not valid Caddyfile syntax — Caddy's `split` subdirective takes a list of file extensions (e.g. `split .php`, for PHP-FPM-style dispatch), not an arbitrary bareword, and `fossh-cgi`'s own routes (`/e`, `/e.gif`) have no extension-based split point to give it anyway. It's removed above. In its place, `env PATH_INFO {http.request.uri.path}` sets `PATH_INFO` explicitly to the real request path — needed because `fossh-cgi`'s own routing matches on `PATH_INFO`, not `SCRIPT_NAME` (`crates/fossh-ingest/src/ingest.rs`'s `decide()`), and without an explicit value here Caddy's fastcgi transport has no extension-based split point to derive one from either, the same class of gap already found and fixed for Apache (`DEPLOY-apache.md`) and nginx (`docs/preview/DEPLOY-nginx-cloudflare-tunnel.md`). The underlying `PATH_INFO` problem is confirmed real (reproduced against a live Apache instance); this specific Caddy directive follows the same well-documented `fastcgi` transport mechanism but — per the notice at the top of this guide — hasn't itself been run against a live Caddy.

## 3. `X-Forwarded-For` — read this before relying on visitor counts

If Caddy itself is directly internet-facing (not behind another proxy like Cloudflare Tunnel), `fcgiwrap`/`fossh-cgi` already sees the real visitor's IP as `REMOTE_ADDR` with no extra configuration — Caddy sets that correctly by default. `FOSSH_TRUST_FORWARDED_FOR` (in `fossh-fcgiwrap.service`'s `Environment=`) is only relevant if Caddy itself sits behind another reverse proxy or tunnel; see `docs/preview/DEPLOY-nginx-cloudflare-tunnel.md`'s note on this same setting for the reasoning — it applies identically here.

## 3.5. Narrowing who can reach `/e`/`/e.gif`

Same reasoning as `DEPLOY-apache.md`'s "Narrowing who can reach
`/e`/`/e.gif`" section — read that section first, including its
important split between a **relay caller** (a fixed, known machine —
`docs/INTEGRATION-php.md`'s shared-hosting client, or your own second
server; narrowing applies here) and a **direct browser beacon**
(`--public-key` sites hit straight from every visitor's own browser;
narrowing does *not* apply, and would break the product, for that
shape). Everything in that section about *why* — the write key already
stops fake events and exfiltration, but not the request from arriving,
and `fossh-ingest`'s own `IpFailBucket` only throttles a single source's
sustained run of auth failures, not a distributed one — applies here
unchanged, since it's about `fossh-cgi` itself, not about which
webserver sits in front of it.

Caddy's own per-route IP restriction is a `@matcher` using `remote_ip`,
placed before the `reverse_proxy`:

```caddyfile
your-site.example {
    @fossh path /e /e.gif
    @not_allowed not remote_ip 203.0.113.10 198.51.100.0/24

    respond @not_allowed 403

    reverse_proxy @fossh unix//run/fossh/fcgiwrap.sock {
        transport fastcgi {
            root /usr/bin
            env SCRIPT_FILENAME /usr/bin/fossh-cgi
            env PATH_INFO {http.request.uri.path}
        }
    }

    respond @fossh 404
}
```

Replace the address(es) with your relay's real, fixed IP. **This
directive, like the rest of this guide, has not been run against a live
Caddy instance** — Caddy's `remote_ip` matcher is standard, documented
behavior, used here the ordinary way, but per this guide's own top
notice, treat it as unverified until you've confirmed it against a real
request from a disallowed address (should get Caddy's own `403`, not
foSSH's `401`). If your relay's source IP isn't fixed (common on cheap
shared hosting), see `DEPLOY-apache.md`'s Option C — a private
WireGuard/SSH link between the two ends, or the zero-inbound-port
Cloudflare Tunnel pattern `docs/preview/DEPLOY-nginx-cloudflare-tunnel.md`
already documents — instead of leaving the port open to an unknown,
rotating address.

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
fossh query --site my-site --from $(date +%F) --to $(date -d tomorrow +%F) --metric hits,uniques
```

`--to` is exclusive, at midnight of that date — `--from`/`--to` set to
the same day is an empty range and always returns zero rows regardless
of whether ingestion actually worked (reproduced directly, see
`DEPLOY-apache.md`'s step 5); use tomorrow's date for `--to` to see
today's events.
