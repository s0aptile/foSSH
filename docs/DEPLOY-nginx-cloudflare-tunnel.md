# Deploying foSSH behind nginx + Cloudflare Tunnel

> **Status: preview, deferred.** This tier is documented for reference and is explicitly *not* part of the Fedora-native hardening chapter tracked in `DURUM.md` — see that chapter's §6. It has not been through the adversarial-review QA gate the rest of this project's deployment surfaces go through. Treat this as a description of the intended shape, not a reviewed, supported path yet. Check `DURUM.md` before following this in production.

This guide covers self-hosting foSSH on a single Fedora Server box, reachable from the public internet with **zero inbound ports opened** — no port forwarding, no firewall rule for 80/443, nothing listening on a public interface at all. Cloudflare Tunnel makes only outbound connections from your box to Cloudflare's edge; the edge terminates public TLS and forwards over that outbound tunnel.

```
visitor's browser
      |
      v
Cloudflare edge (TLS terminates here)
      |
      v  (outbound-only tunnel, no listening port on your box)
cloudflared  --------------------------------------------\
      |                                                    |
      v                                                    |
nginx (loopback only, 127.0.0.1)                           |
      |                                                    |
      v                                                    |
fcgiwrap  ---spawns--->  fossh-cgi  ---writes--->  fossh.db (this host only)
```

Only `fossh-cgi`'s two public ingest routes (`/e`, `/e.gif`, per §7/§8 of the implementation spec) are meant to sit behind this tunnel. The local TUI admin console (chapter §3.9) is explicitly out of scope for network exposure — it talks to the watchdog over a local QUIC/Unix-socket channel only, and this guide does not change that.

## 1. Prerequisites

- Fedora Server with `foSSH` already installed and a site created (`fossh init`, `fossh site create <slug>` — see the main README).
- A domain managed in Cloudflare (free tier is enough).
- Root/sudo on the box, run by you — nothing here asks an agent or script for your password; every privileged step below is a command you run yourself.

## 2. nginx + fcgiwrap (serving `fossh-cgi` as CGI)

`fossh-cgi` speaks plain CGI (RFC 3875), not FastCGI — nginx doesn't spawn CGI processes itself, so `fcgiwrap` bridges FastCGI-from-nginx to a CGI-style `exec` of the `fossh-cgi` binary per request, handing it exactly the RFC 3875 environment it expects.

```
sudo dnf install nginx fcgiwrap
```

Use the actual hardened units this project ships (chapter §3.2) rather than a hand-rolled socket/service — copy them in and enable:

```
sudo cp packaging/systemd/fossh-fcgiwrap.socket packaging/systemd/fossh-fcgiwrap.service /etc/systemd/system/
sudo cp packaging/systemd/fossh.tmpfiles.conf /usr/lib/tmpfiles.d/fossh.conf
sudo systemd-tmpfiles --create
sudo systemctl enable --now fossh-fcgiwrap.socket
```

These listen on `/run/fossh/fcgiwrap.sock` (not a bare TCP port) and run under `PrivateNetwork=yes`/`ProtectSystem=strict`/SELinux confinement — see the unit files themselves and `packaging/selinux/fossh.te` for what that actually grants. nginx talks to that same socket:

```nginx
server {
    listen 127.0.0.1:8080;
    server_name _;

    # Cloudflare Tunnel terminates the real visitor connection at its edge
    # and forwards to nginx over loopback — from nginx's point of view the
    # peer is cloudflared (127.0.0.1), not the visitor. Without this,
    # REMOTE_ADDR would be 127.0.0.1 for every single visitor, collapsing
    # everyone into one "visitor" for foSSH's hashing. This tells nginx to
    # trust cloudflared's own CF-Connecting-IP header instead, for
    # connections that actually come from loopback.
    set_real_ip_from 127.0.0.1;
    real_ip_header CF-Connecting-IP;

    location ~ ^/(e|e\.gif)$ {
        include fastcgi_params;
        fastcgi_pass unix:/run/fossh/fcgiwrap.sock;
        fastcgi_param SCRIPT_FILENAME /usr/bin/fossh-cgi;
    }

    location / {
        return 404;
    }
}
```

With `real_ip_header` handling this at the nginx layer, `fossh-cgi` sees the correct `REMOTE_ADDR` directly and does **not** need `FOSSH_TRUST_FORWARDED_FOR` for this deployment shape specifically — that setting exists for a different case (a shared-hosting PHP script relaying server-side with no nginx/real-ip-module equivalent in front of it; see `docs/INTEGRATION-php.md`), not this one. Don't enable it here on top of `real_ip_header` — one visitor-IP-trust mechanism at a time is enough, and stacking both just means whichever runs first wins with no benefit.

Note the `listen 127.0.0.1:8080` — nginx itself never binds a public interface here either. The only thing that ever touches the public internet is Cloudflare's edge.

## 3. Cloudflare Tunnel

```
sudo dnf config-manager --add-repo https://pkg.cloudflare.com/cloudflared.repo
sudo dnf install cloudflared
cloudflared tunnel login
cloudflared tunnel create fossh
cloudflared tunnel route dns fossh analytics.yourdomain.example
```

`/etc/cloudflared/config.yml`:

```yaml
tunnel: fossh
credentials-file: /etc/cloudflared/<tunnel-id>.json

ingress:
  - hostname: analytics.yourdomain.example
    service: http://127.0.0.1:8080
  - service: http_status:404
```

```
sudo systemctl enable --now cloudflared
```

At this point `https://analytics.yourdomain.example/e.gif` reaches `fossh-cgi`, and nothing on the box has an open inbound port. `firewall-cmd --list-all` should show no new rule was needed — that's the point, not an oversight.

## 4. Optional: Cloudflare Access in front

If you later put anything admin-facing behind a hostname routed through this same tunnel (not recommended for the TUI specifically — see the scope note above), gate it with Cloudflare Access rather than relying on the tunnel alone. Access sits in front of the ingress rule and enforces its own auth (identity provider, one-time PIN, etc.) before a request ever reaches nginx.

## 5. What this guide does not cover yet

- Automated certificate/tunnel provisioning as part of the RPM's setup wizard (chapter §3.11's wizard targets the local TUI flow only; wiring a tunnel is a manual step here).
- Multi-site nginx routing (one `server{}` block per site slug) — write one per site as needed, following the pattern above.
- An adversarial security review of this specific tier — see the preview notice at the top.
