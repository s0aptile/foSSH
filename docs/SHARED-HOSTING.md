# foSSH on real shared hosting

For hosting with no shell, no Composer, and no SSH — FTP or your host's
File Manager only. If you have a shell, `docs/INTEGRATION-php.md` covers
the fuller client instead; this page is deliberately narrower.

[`docs/fossh-config.php`](fossh-config.php) is the smallest possible way
to get foSSH pageview tracking onto a shared-hosting PHP site. It does
exactly one thing — record one page view, automatically, the moment it
is included — and nothing else. For events, timings, or the FFI and
CGI-subprocess transports, use `bindings/php/src/Client.php`.

These instructions used to live in that file's own header comment. They
are here now because the source files carry no comments; the file itself
is unchanged in what it does.

## Three steps, none of which need a shell on the shared host

### 1. Create a write key

Somewhere you *do* control — a VPS, a Fedora box, anywhere foSSH is
actually installed and running, **not** the shared host — run:

```
fossh site create your-site-name --allow pageview
```

This prints a write key exactly once, shaped
`fossh_your-site-name_<random>`. Copy it now. It is never shown again.
If you lose it, `fossh site rotate-key your-site-name` issues a new one
and invalidates the old.

### 2. Fill in the two blanks

Open `fossh-config.php` and set the two constants at the top:

| Constant | What goes in it |
|---|---|
| `FOSSH_KEY` | The write key from step 1 |
| `FOSSH_ENDPOINT` | The `https://` address your foSSH instance answers on |

cPanel or Plesk's built-in File Manager editor works, and so does
download-edit-reupload over FTP. Either is fine.

The endpoint must be `https://`. The write key travels as a bearer
token on every request, so over plain `http://` it would be readable by
anything between your shared host and your server. The file refuses to
send anything if the endpoint is not `https://`, rather than sending it
anyway.

### 3. Include it once

Upload the file anywhere your PHP can reach, then add one line near the
top of the pages you want tracked:

```php
require_once '/full/path/to/fossh-config.php';
```

A shared header or template file is usually the one right place to add
it once for a whole site.

Use `require_once` and not `require`. The file guards every definition
it makes, so a second include is harmless, but `require_once` is the
plainer way to say what you mean.

## What happens if something is wrong

Nothing visible, by design. A page render never fails because telemetry
did:

- Blanks left unfilled: the file does nothing at all.
- foSSH unreachable, or slow: at most about two seconds, then it gives
  up quietly.
- Endpoint set to `http://`: refuses to send, and says why in your PHP
  error log.
- No `curl` extension: falls back to PHP's own stream wrapper. Neither
  available: does nothing.

## Getting per-visitor counts right

Your shared host relays to foSSH, so the connection foSSH sees comes
from the shared host rather than from your visitor. Left alone, every
visitor collapses into one. `docs/INTEGRATION-php.md` has the section on
`FOSSH_TRUST_FORWARDED_FOR` — read it before enabling it, particularly
the part about restricting who can reach the foSSH side, which is a
requirement rather than a suggestion.
