<?php

declare(strict_types=1);

/**
 * =============================================================
 *  foSSH drop-in tracker — for real shared hosting (no shell,
 *  no Composer, no SSH — FTP or your host's File Manager only).
 * =============================================================
 *
 * What this is: the smallest possible way to get foSSH pageview
 * tracking on a shared-hosting PHP site. It does exactly one thing —
 * record one page view, automatically, the moment it's included — and
 * nothing else. If you want events, timings, or the full client
 * (FFI/CGI-subprocess modes, not just HTTP), use
 * `bindings/php/src/Client.php` instead; this file is deliberately
 * narrower than that.
 *
 * Setup (three steps, no shell needed for any of them):
 *
 *   1. Somewhere you *do* control (a VPS, a Fedora box, anywhere
 *      foSSH is actually installed and running) — not on the shared
 *      host itself — run:
 *
 *          fossh site create your-site-name --allow pageview
 *
 *      This prints a write key exactly once, shaped like
 *      `fossh_your-site-name_<random>`. Copy it now; it is never
 *      shown again (`fossh site rotate-key` issues a new one if you
 *      lose it, invalidating the old one).
 *
 *   2. Fill in the two blanks below — FOSSH_KEY and FOSSH_ENDPOINT —
 *      by editing *this* file directly (cPanel/Plesk File Manager's
 *      built-in editor, or download-edit-reupload over FTP both work
 *      identically fine).
 *
 *   3. Upload/save this file anywhere your PHP can `require` it, then
 *      add exactly one line near the top of whichever page(s) you
 *      want tracked (a shared header/template file is usually the
 *      one right place to add it once for a whole site):
 *
 *          require_once '/full/path/to/fossh-config.php';
 *
 *      Use `require_once`, not `require` — see the redeclaration
 *      guards below for why that matters if this file is ever reached
 *      more than once in the same request.
 *
 * That's the entire integration. No further code, no JavaScript
 * snippet, no cookie banner needed — foSSH never sets a cookie and
 * never loads a client-side script.
 *
 * Foolproof by design: leaving the blanks empty, a typo in either one,
 * the foSSH instance being briefly unreachable, or `curl`/
 * `allow_url_fopen` both being disabled on this host all fall through
 * to doing nothing at all — never a fatal error, never a broken page.
 * This file cannot take your site down; the worst case is that a page
 * view silently isn't recorded.
 *
 * Requires PHP 7.4 or later (matches `bindings/php`'s own minimum —
 * real shared hosting is exactly where an older PHP is most likely,
 * so this file deliberately avoids anything newer, most notably
 * `str_starts_with()`, PHP 8.0+ only).
 */

// =====================================================================
// FILL IN THESE TWO — everything below this block is not meant to be
// edited.
// =====================================================================

// From step 1 above. Looks like: fossh_your-site-name_ABCDEF23456...
if (!defined('FOSSH_KEY')) {
    define('FOSSH_KEY', '');
}

// The https:// address of the foSSH instance you set up in step 1 —
// e.g. https://analytics.yourdomain.example (no trailing slash, and
// it must be https:// — see the check below for why plain http:// is
// refused outright rather than silently allowed).
if (!defined('FOSSH_ENDPOINT')) {
    define('FOSSH_ENDPOINT', '');
}

// Purely informational. Does not change anything this file does, on
// purpose: foSSH never sets cookies and never loads a client-side
// script, so running it alongside Google Analytics/Google Ads needs
// no special handling on either side — see this project's own
// RULES.md §5 if you want the reasoning. This constant exists only so
// *you* have one place, in your own config, that records whether this
// site also has a Google product installed — nothing reads it but you.
//   'f' (default) — no Google Analytics/Ads on this site.
//   't'           — yes, both run here, side by side, on purpose.
if (!defined('FOSSH_GPRODUCTS')) {
    define('FOSSH_GPRODUCTS', 'f');
}

// =====================================================================
// Nothing below this line is meant to be edited.
//
// Every name below is guarded (function_exists/defined) rather than
// declared unconditionally, and the one line that actually does
// something runs inside an anonymous, immediately-invoked function —
// not a named one. Between them, this file tolerates being reached
// more than once in the same request (a second `fossh-config.php` in
// a different folder for a different site under the same hosting
// account, say) without a PHP fatal "cannot redeclare" error. It will
// send a second page view in that specific case, which is a mildly
// inflated count, not a broken site — `require_once` in step 3 above
// avoids even that for the normal case of one file, included once.
// =====================================================================

if (!function_exists('fossh_strip_header_injection')) {
    /**
     * Strips CR/LF from a value that is about to become part of a raw
     * HTTP header line — without this, an attacker-controlled
     * User-Agent/IP containing an embedded newline could inject an
     * additional, unintended header into this request. Returns null
     * unchanged (nothing to strip).
     */
    function fossh_strip_header_injection(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }
        return str_replace(["\r", "\n"], '', $value);
    }
}

if (!function_exists('fossh_send')) {
    /**
     * Fire-and-forget-ish: a short-timeout HTTPS GET, curl if
     * available, falling back to a plain stream context if not, doing
     * nothing at all if neither is available on this host. Never
     * throws — the one invariant this whole file exists to guarantee.
     *
     * @param string[] $headers
     */
    function fossh_send(string $url, array $headers): void
    {
        try {
            if (\function_exists('curl_init')) {
                $ch = curl_init($url);
                if ($ch !== false) {
                    curl_setopt_array($ch, [
                        CURLOPT_RETURNTRANSFER => true,
                        CURLOPT_CONNECTTIMEOUT_MS => 1500,
                        CURLOPT_TIMEOUT_MS => 2000,
                        CURLOPT_HTTPHEADER => $headers,
                        // The https:// check below guards the URL you
                        // paste in. It cannot guard where that URL then
                        // redirects to: a 302 to a plain http:// address
                        // would have the Authorization header — your
                        // write key — resent in the clear. So redirects
                        // are simply not followed.
                        CURLOPT_FOLLOWLOCATION => false,
                    ]);
                    curl_exec($ch);
                    curl_close($ch);
                }
                return;
            }
            if (\filter_var(\ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN)) {
                $context = stream_context_create([
                    'http' => [
                        'method' => 'GET',
                        'header' => implode("\r\n", $headers),
                        'timeout' => 2.0,
                        'ignore_errors' => true,
                        // Same reason as CURLOPT_FOLLOWLOCATION above,
                        // and here it matters more: PHP's HTTP stream
                        // wrapper follows redirects by default and
                        // carries these headers across.
                        'follow_location' => 0,
                    ],
                ]);
                @file_get_contents($url, false, $context);
            }
            // Neither transport available: documented no-op, not an error.
        } catch (\Throwable $e) {
            // Never let a telemetry failure become a visible failure
            // on the host site — see this file's own header comment.
        }
    }
}

(function (): void {
    if (FOSSH_KEY === '' || FOSSH_ENDPOINT === '') {
        return; // blanks not filled in yet — silently do nothing
    }
    // PHP 7.4-compatible equivalent of str_starts_with() (PHP 8.0+) —
    // see this file's own header comment on why that matters here
    // specifically. FOSSH_KEY is a bearer credential (§8 of the
    // implementation spec) sent as an Authorization header on every
    // call; sending it over plain http:// would put it on the wire in
    // cleartext for anyone positioned to observe it — the one thing
    // this file will not do quietly, even if someone pastes an
    // http:// URL in here by mistake.
    if (substr(FOSSH_ENDPOINT, 0, 8) !== 'https://') {
        return;
    }

    $path = $_SERVER['REQUEST_URI'] ?? null;
    $referrer = $_SERVER['HTTP_REFERER'] ?? null;
    $userAgent = fossh_strip_header_injection($_SERVER['HTTP_USER_AGENT'] ?? null);
    $visitorIp = fossh_strip_header_injection($_SERVER['REMOTE_ADDR'] ?? null);

    $query = array_filter(
        ['name' => 'pageview', 'path' => $path, 'referrer' => $referrer],
        static function ($v) {
            return $v !== null;
        }
    );
    $url = rtrim(FOSSH_ENDPOINT, '/') . '/e.gif?' . http_build_query($query);

    $headers = ['Authorization: Bearer ' . FOSSH_KEY];
    if ($userAgent !== null) {
        $headers[] = 'User-Agent: ' . $userAgent;
    }
    if ($visitorIp !== null) {
        // Honored by the receiving foSSH instance only if its own
        // operator explicitly opted in (FOSSH_TRUST_FORWARDED_FOR=1) —
        // see docs/INTEGRATION-php.md. Without that, every visitor
        // relayed through this site still gets recorded, just
        // collapsed toward this shared-hosting account's own egress
        // IP for hashing purposes — degraded uniqueness, not broken.
        $headers[] = 'X-Forwarded-For: ' . $visitorIp;
    }

    fossh_send($url, $headers);
})();
