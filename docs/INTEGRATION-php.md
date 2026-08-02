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

### Getting correct per-visitor stats: `FOSSH_TRUST_FORWARDED_FOR`

This part matters and is easy to get silently wrong. When your shared-hosting PHP relays a request to your foSSH instance, the TCP connection *to foSSH* comes from the shared host's own server — not from your actual visitor. Left unhandled, every visitor across your entire shared-hosting account would collapse into a single "visitor" as far as foSSH's hashing is concerned, because they'd all appear to arrive from the same IP.

The client already forwards the real visitor's IP and User-Agent (`X-Forwarded-For` / `User-Agent` headers) on every relayed call. Nothing further is needed on the shared-hosting side. But foSSH only *honors* that forwarded IP if you tell it to — on the machine actually running foSSH, set:

```
FOSSH_TRUST_FORWARDED_FOR=1
```

(in `fossh-cgi`'s environment — see `packaging/systemd/fossh-fcgiwrap.service` if you're running the Fedora-native deployment, or your CGI/FastCGI config's environment block otherwise). This is off by default on purpose — it's only correct to enable if you know the traffic reaching foSSH is coming through something that legitimately relays on a visitor's behalf, which a shared-hosting relay is, but an arbitrary untrusted caller isn't. See `DECISIONS.md`'s ADR-0025 if you want the full reasoning.

If you skip this step, tracking still works, it just undercounts unique visitors from that site — not a crash, just degraded numbers, which is easy to miss if you don't know to look for it.

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

Laravel/Symfony middleware wrappers are planned but not shipped yet — track `DURUM.md`/M6 for status; the plain `Client` above works from either framework's own middleware today with a few lines, same as the WordPress hook above.
