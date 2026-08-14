# PHP integration

`bindings/php` (`FoSSH\Client`, namespace `s0aptile/fossh-php`) works two different ways depending on where your PHP actually runs:

- **You control the server** (a VPS, your own Fedora box, anywhere with shell access) and foSSH runs on the same machine or one you can reach directly. Use FFI (fastest, in-process) or the CGI-subprocess fallback. See the "Same-server modes" section below.
- **Real shared hosting** (cPanel, a hosting panel, no shell, `ext-ffi` usually unavailable, `proc_open` often disabled too) — the realistic setup is: foSSH runs somewhere *you* control (a small VPS or Fedora box, or eventually a hosted offering), and the shared-hosting PHP makes a plain HTTPS call to it. This is the main case this document covers, because it's the one that actually works on a typical shared host.

Either way, the write key is the same thing `fossh site create` already prints — see the next section for what "shared hosting" specifically needs from it.

## 1. Creating an API key

Run this on the machine actually running foSSH (not on the shared host — shared hosting has no shell to run this from):

```
fossh site create my-site --allow pageview,signup,checkout
```

This prints a write key shaped `fossh_my-site_<base32>` exactly once. Treat it like a password: it's the only credential the shared-hosting side needs, and anyone holding it can submit events to that site. It is not tied to a domain or an IP — it works from wherever you put it.

## 2. Shared hosting: HTTP-remote mode

```
composer require s0aptile/fossh-php
```

```php
$fossh = new \FoSSH\Client(
    remoteEndpoint: 'https://analytics.yourdomain.example', // where foSSH actually runs
    key: getenv('FOSSH_KEY'),                                 // the write key from step 1
);
$fossh->pageview();
$fossh->event('checkout', 1, ['tier' => 'pro']);
```

Or set `FOSSH_ENDPOINT`/`FOSSH_KEY` as environment variables (most hosting panels have a place to set these per-site) and construct with no arguments — `new \FoSSH\Client()` reads both.

This makes a plain outbound HTTPS request per call (`curl` if the extension is available, otherwise PHP's own stream wrapper — nothing beyond stock PHP is required), authenticated with the write key as a bearer token. It never touches `ext-ffi` or `proc_open`, which is why it's the one that actually works on a locked-down shared host. A slow or unreachable foSSH endpoint costs at most ~2 seconds (the built-in timeout) and never throws — a page render never fails because telemetry did.

### Restricting who can reach the foSSH side of this

This transport necessarily means two different machines talking over the public internet: `remoteEndpoint` above has to be reachable from wherever this PHP actually runs, which means it's also reachable by anyone else who finds the same address — not just this client. This applies whether the caller is real shared hosting or your own second server relaying on a site's behalf; the shape (a fixed, known caller reaching a foSSH instance that isn't on the same box) is identical either way, and so is the fix.

The write key remains the actual thing standing between an anonymous caller and a forged event or a data leak — verified directly against the compiled `fossh-cgi` binary: every failure mode (no key, a malformed token, an unknown site, a wrong key, a disabled site) answers the identical `401`, no body, nothing to distinguish one from another, and there is no read/query route on this path for anything to leak through even under active probing. What it doesn't do on its own is stop an anonymous caller's requests from *arriving*: `fossh-ingest` throttles a single source's sustained run of auth failures (`429` after 20 attempts), but that's a source-IP-keyed backstop, not a substitute for controlling who can reach the port at all — a determined or distributed caller with no key still costs the backend something on every attempt, and each one still passes through the webserver in front of `fossh-cgi`/`fossh-fcgi` before ever getting refused.

So: on the machine actually running foSSH, restrict inbound connections on `remoteEndpoint`'s port to the calling PHP host's own known, fixed IP address(es) — see `docs/DEPLOY-apache.md`'s "Narrowing who can reach `/e`/`/e.gif`" section for exact commands (an Apache `Require ip` directive scoped to just these two routes, or a `firewalld` rule if the whole box is dedicated to this install) and `docs/DEPLOY-caddy.md`'s equivalent if you're running Caddy instead. This is defense-in-depth on top of the write-key model, not a replacement for it — do this *in addition to* treating the write key like a password, not instead of it.

**If the calling host's own outbound IP isn't fixed or knowable** (common on cheap shared hosting, where it can rotate) — don't leave the port open to the whole internet "just in case" the write key alone is enough. Put a private link between the two ends instead: a point-to-point WireGuard connection, or an SSH reverse tunnel if that's all the shared host can run. Either means the foSSH side never has an ingest port listening on a public interface at all, the same zero-inbound-port shape `docs/preview/DEPLOY-nginx-cloudflare-tunnel.md` documents for a different case (a site's own visitors hitting a public-key beacon directly, where source IPs can't be restricted at all — see that guide's own scope note). A fixed relay caller doesn't need that guide's Cloudflare-edge/public-DNS machinery; a plain point-to-point tunnel between exactly the two machines involved is simpler and does the same job.

**One important exception, if this same foSSH instance also serves a `--public-key` site used as a direct browser beacon (client-side JS calling `/e.gif` from real visitors, not this PHP client):** none of the network-restriction advice above applies to that site's own traffic — its whole point is accepting requests from arbitrary visitor IPs, and narrowing the port by source address would break it. That shape relies on the write-key model alone, which — per the halved rate limit §8 already gives public keys, and everything verified above — is the intended, sufficient defense for it. Narrowing by IP only makes sense when *every* caller reaching this port is a fixed relay like this PHP client, never when any of them is a browser.

### No Composer either? `docs/fossh-config.php`

Some shared hosting has no shell at all — no SSH, so no way to run `composer require` in the first place, only FTP or a hosting panel's own File Manager. For that case, skip `bindings/php` entirely and use [`docs/fossh-config.php`](fossh-config.php): a single, self-contained file with two blanks (the write key from step 1, and the `https://` address foSSH runs at). Fill them in by editing the file directly, upload it anywhere your PHP can reach, add one `require_once` line to your site, and it records a page view automatically on every include — no Composer, no other file it depends on, and it cannot fatal your site even if the blanks are left empty or the foSSH endpoint is briefly unreachable. Read the file's own header comment for the exact three steps; it's written for the same non-technical, FTP-only audience this whole section exists for.

### Getting correct per-visitor stats: `FOSSH_TRUST_FORWARDED_FOR`

This part matters and is easy to get silently wrong. When your shared-hosting PHP relays a request to your foSSH instance, the TCP connection *to foSSH* comes from the shared host's own server — not from your actual visitor. Left unhandled, every visitor across your entire shared-hosting account would collapse into a single "visitor" as far as foSSH's hashing is concerned, because they'd all appear to arrive from the same IP.

The client already forwards the real visitor's IP and User-Agent (`X-Forwarded-For` / `User-Agent` headers) on every relayed call. Nothing further is needed on the shared-hosting side. But foSSH only *honors* that forwarded IP if you tell it to — on the machine actually running foSSH, set:

```
FOSSH_TRUST_FORWARDED_FOR=1
```

(in `fossh-cgi`'s environment — see `packaging/systemd/fossh-fcgiwrap.service` if you're running the Fedora-native deployment, or your CGI/FastCGI config's environment block otherwise). This is off by default on purpose — it's only correct to enable if you know the traffic reaching foSSH is coming through something that legitimately relays on a visitor's behalf, which a shared-hosting relay is, but an arbitrary untrusted caller isn't. See `DECISIONS.md`'s ADR-0025 if you want the full reasoning.

If you skip this step, tracking still works, it just undercounts unique visitors from that site — not a crash, just degraded numbers, which is easy to miss if you don't know to look for it.

**Turning this on without also doing the "Restricting who can reach the foSSH side of this" step above quietly voids `IpFailBucket`'s protection.** `IpFailBucket` (`crates/fossh-ingest/src/ratelimit.rs`) throttles a sustained run of auth failures by hashing the same client-IP value everything else on this page uses — and once `FOSSH_TRUST_FORWARDED_FOR=1` is set, that value *is* `X-Forwarded-For`, taken as-is from whoever's TCP connection actually reaches `fossh-cgi`. If the port is still open to the whole internet at that point (the "Restricting" section above not yet applied), anyone can reach it directly — not just your relay — and send a fresh, made-up `X-Forwarded-For` value on every single request. Each fabricated value gets its own untouched 20-attempt allowance, so the flood never accumulates against any one bucket and never trips `429` at all — confirmed directly against the compiled binary: 40 straight wrong-key requests, each with a distinct spoofed `X-Forwarded-For`, all came back `401`, never once `429`, under this exact configuration. The write key remains intact either way (nothing here weakens authentication itself), but the availability backstop this page's "Restricting who can reach the foSSH side of this" section and `IpFailBucket` are supposed to provide is gone. Do the restricting step first, or alongside this one — not after "eventually."

### WordPress

The same client works from a plugin or a theme's `functions.php`:

```php
add_action('wp_footer', function () {
    static $fossh = null;
    $fossh ??= new \FoSSH\Client(
        remoteEndpoint: getenv('FOSSH_ENDPOINT'),
        key: getenv('FOSSH_KEY'),
    );
    $fossh->pageview();
});
```

Hook a specific action (e.g. `woocommerce_thankyou`) the same way to send an `event()` for something more specific than a pageview.

## 3. Alongside Google Analytics / Tag Manager

foSSH doesn't require removing anything else you're already running. The PHP client makes its own server-side HTTPS call — it doesn't set cookies, doesn't touch `window.dataLayer` or `gtag`, doesn't load any client-side script at all, and has no way to conflict with GA/GTM's own tags on the same page. Running both is a normal, supported configuration if you want GA's ad-attribution features alongside foSSH's privacy-preserving numbers for your own use — they're answering different questions, not competing for the same one.

## 4. Same-server modes (FFI / CGI-subprocess)

If your PHP runs on the same machine as foSSH (or one where you can install the shared library):

```php
$fossh = new \FoSSH\Client('/etc/fossh/fossh.toml', getenv('FOSSH_KEY'));
```

With `ext-ffi` enabled and `libfossh.so` on the library path (`FOSSH_LIB_PATH` to override), this calls into foSSH in-process — no network round trip at all. If `ext-ffi` isn't enabled, pass `cgiBinaryPath` (or set `FOSSH_CGI_BIN`) to fall back to spawning the `fossh-cgi` binary per call instead. Transport is chosen automatically, in this order: FFI, then HTTP (if `remoteEndpoint`/`FOSSH_ENDPOINT` is set), then CGI-subprocess (if `cgiBinaryPath`/`FOSSH_CGI_BIN` is set), then a documented no-op if none of the above apply — never a fatal error in your application either way.

## 5. Reference

| Constructor argument | Env var fallback | Used by |
|---|---|---|
| `configPath` | `FOSSH_CONFIG`-style search (same as the CLI) | FFI mode only |
| `key` | `FOSSH_KEY` | FFI (`fossh_set_key`) and HTTP mode (bearer token) |
| `remoteEndpoint` | `FOSSH_ENDPOINT` | HTTP mode |
| `cgiBinaryPath` | `FOSSH_CGI_BIN` | CGI-subprocess mode |

Methods: `pageview()`, `event(string $name, int $value = 1, ?array $props = null)`, `timing(string $name, int $millis)`, `flush()`, `lastError()` (FFI mode only — the other transports don't have a session to ask).

Laravel/Symfony middleware wrappers ship under `bindings/php/src/Laravel/FosshMiddleware.php` and `bindings/php/src/Symfony/FosshRequestSubscriber.php` — register either the same way you'd register any other middleware/subscriber in that framework. The plain `Client` above still works directly from either framework with a few lines, same as the WordPress hook above, if you'd rather not add the wrapper.
