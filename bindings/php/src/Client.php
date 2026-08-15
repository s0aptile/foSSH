<?php

declare(strict_types=1);

namespace FoSSH;

/**
 * Wrapper around foSSH with three transports, tried in order, each
 * falling through to the next rather than ever raising — telemetry
 * must never be able to take the host application down:
 *
 *  1. FFI (`ext-ffi`, in-process, fastest) — needs the extension
 *     enabled and a local `libfossh.so`. Rare on real shared hosting.
 *  2. HTTP (`$remoteEndpoint` configured) — a plain HTTPS call, using
 *     the write key as a Bearer token, to a foSSH instance running
 *     wherever you actually host it. This is the one that works on
 *     ordinary shared hosting: no compiled extension, no `proc_open`,
 *     just outbound HTTPS, which is close to universally available
 *     even on locked-down hosts. See docs/INTEGRATION-php.md.
 *  3. CGI-subprocess (`$cgiBinaryPath` configured) — spawns the
 *     `fossh-cgi` binary per call. Needs `proc_open` and a local
 *     binary; more relevant to a VPS than real shared hosting.
 *  4. No-op — nothing configured, or everything above failed.
 *
 * The FFI declarations below are a small, hand-maintained subset of
 * include/fossh.h, not that file parsed at runtime: FFI::cdef() only
 * understands a simplified C subset (no preprocessor, no C11
 * conditional-underlying-type enum syntax), so feeding it the real,
 * cbindgen-generated header — which has both — doesn't work. Keep this
 * in sync by hand with include/fossh.h when the C ABI changes; it's
 * intentionally the smallest possible mirror, not a general parser.
 */
final class Client
{
    private const CDEF = <<<'CDEF'
        typedef struct fossh_ctx fossh_ctx;
        uint32_t fossh_abi_version(void);
        fossh_ctx *fossh_init(const char *config_path);
        void fossh_free(fossh_ctx *ctx);
        int32_t fossh_last_error(const fossh_ctx *ctx, char *buf, size_t len);
        int32_t fossh_set_key(fossh_ctx *ctx, const char *key);
        int32_t fossh_pageview(fossh_ctx *ctx, const char *path, const char *referrer, const char *client_ip, const char *user_agent);
        int32_t fossh_event(fossh_ctx *ctx, const char *name, int64_t value, const char *props_json);
        int32_t fossh_timing(fossh_ctx *ctx, const char *name, int64_t millis);
        int32_t fossh_flush(fossh_ctx *ctx);
        CDEF;

    /** Ceiling on how long a `fossh-cgi` subprocess may hold up the host request. */
    private const CGI_TIMEOUT_SECS = 2.0;

    private ?\FFI $ffi = null;
    /** @var \FFI\CData|null */
    private $ctx = null;
    private bool $usable = false;
    private ?string $key;
    private ?string $remoteEndpoint;
    private ?string $cgiBinaryPath;

    public function __construct(
        ?string $configPath = null,
        ?string $key = null,
        ?string $cgiBinaryPath = null,
        ?string $remoteEndpoint = null
    ) {
        $this->key = $key ?? (getenv('FOSSH_KEY') ?: null);
        $this->remoteEndpoint = self::vetEndpoint(
            rtrim($remoteEndpoint ?? (getenv('FOSSH_ENDPOINT') ?: ''), '/') ?: null
        );
        $this->cgiBinaryPath = $cgiBinaryPath ?? (getenv('FOSSH_CGI_BIN') ?: null);

        if (!\extension_loaded('ffi')) {
            return; // falls through to HTTP, then CGI-subprocess, then a no-op
        }

        try {
            $libPath = getenv('FOSSH_LIB_PATH') ?: 'libfossh.so';
            $this->ffi = \FFI::cdef(self::CDEF, $libPath);
        } catch (\Throwable $e) {
            $this->ffi = null;
            return;
        }

        $ctx = $this->ffi->fossh_init($configPath);
        if (\FFI::isNull($ctx)) {
            $this->ffi = null;
            return;
        }
        $this->ctx = $ctx;

        // `$this->key`, not `$key`: the constructor parameter is only
        // half the story — `FOSSH_KEY` is the documented way to
        // configure this on shared hosting, and reading the raw
        // parameter here meant an install using the env var built a
        // keyless FFI context, marked it usable, and then had every
        // pageview()/event()/timing() rejected forever with no
        // fallback to HTTP or CGI. Silent, permanent, total data loss
        // for the configuration the docs recommend.
        if ($this->key !== null) {
            $rc = $this->ffi->fossh_set_key($this->ctx, $this->key);
            if ($rc !== 0) {
                $this->ffi = null;
                $this->ctx = null;
                return;
            }
        }

        $this->usable = true;
    }

    /**
     * Refuses to keep a remote endpoint that would send the write key
     * in cleartext.
     *
     * `sendHttp()` puts the key in an `Authorization: Bearer` header on
     * every call. Over `http://` that is the whole credential, in the
     * clear, on every page view of the site — recoverable by anything
     * between this server and the endpoint, and it grants write access
     * to the operator's analytics until they notice and rotate it.
     *
     * `http://` to a loopback address is allowed, because it never
     * leaves the machine and is a normal way to run foSSH beside PHP on
     * one box. Everything else must be `https://`.
     *
     * Rejection drops the endpoint rather than throwing — this class
     * does not raise — but it emits an `E_USER_WARNING` so the reason
     * lands in the PHP error log instead of the operator being left to
     * wonder why nothing records.
     */
    private static function vetEndpoint(?string $endpoint): ?string
    {
        if ($endpoint === null) {
            return null;
        }

        $scheme = strtolower((string) parse_url($endpoint, PHP_URL_SCHEME));
        if ($scheme === 'https') {
            return $endpoint;
        }

        if ($scheme === 'http' && self::isLoopback($endpoint)) {
            return $endpoint;
        }

        trigger_error(
            'foSSH: refusing to use endpoint ' . $endpoint . ' — the write key is sent as a '
            . 'Bearer token on every request, so the endpoint must be https:// (or http:// to '
            . 'loopback). Telemetry is disabled until this is corrected.',
            E_USER_WARNING
        );
        return null;
    }

    /**
     * True only for a host that cannot leave this machine.
     *
     * The test is deliberately on a parsed IP literal rather than on
     * the text of the host. `str_starts_with($host, '127.')` reads as
     * equivalent and is not: `127.0.0.1.evil.tld` is a perfectly
     * registrable domain name that satisfies it, resolves to whatever
     * its owner likes, and would have been handed the write key in
     * cleartext by the very check meant to prevent that. Caught by this
     * binding's own test case of the same name.
     *
     * `localhost` is accepted by name because it is the one hostname
     * whose loopback meaning is guaranteed by RFC 6761 rather than by
     * DNS.
     */
    private static function isLoopback(string $endpoint): bool
    {
        $host = strtolower(trim((string) parse_url($endpoint, PHP_URL_HOST), '[]'));
        if ($host === 'localhost') {
            return true;
        }
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return inet_pton($host) === inet_pton('::1');
        }
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            // The whole 127.0.0.0/8 block, not just 127.0.0.1.
            return (ip2long($host) & 0xFF000000) === (127 << 24);
        }
        return false;
    }

    public function __destruct()
    {
        if ($this->usable && $this->ctx !== null && $this->ffi !== null) {
            $this->ffi->fossh_free($this->ctx);
        }
    }

    /** Records a page view, reading path/referrer/IP/UA from $_SERVER. */
    public function pageview(): bool
    {
        $path = $_SERVER['REQUEST_URI'] ?? null;
        $referrer = $_SERVER['HTTP_REFERER'] ?? null;
        $ip = $_SERVER['REMOTE_ADDR'] ?? null;
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;

        if ($this->usable) {
            $rc = $this->ffi->fossh_pageview($this->ctx, $path, $referrer, $ip, $ua);
            return $rc === 0;
        }

        $params = array_filter([
            'name' => 'pageview',
            'path' => $path,
            'referrer' => $referrer,
        ], static fn ($v) => $v !== null);

        if ($this->remoteEndpoint !== null) {
            return $this->sendHttp('GET', '/e.gif', $params, null);
        }
        return $this->fallbackToCgi('/e.gif', $params, $ip, $ua);
    }

    /** @param array<string,string>|null $props */
    public function event(string $name, int $value = 1, ?array $props = null): bool
    {
        if ($this->usable) {
            $propsJson = $props !== null ? json_encode($props, JSON_THROW_ON_ERROR) : null;
            $rc = $this->ffi->fossh_event($this->ctx, $name, $value, $propsJson);
            return $rc === 0;
        }

        if ($this->remoteEndpoint !== null) {
            $body = ['name' => $name, 'value' => $value];
            if ($props !== null) {
                $body['props'] = $props;
            }
            return $this->sendHttp('POST', '/e', [], json_encode($body, JSON_THROW_ON_ERROR));
        }

        $params = ['name' => $name, 'value' => (string) $value];
        foreach ($props ?? [] as $k => $v) {
            $params["props.{$k}"] = $v;
        }
        return $this->fallbackToCgi('/e', $params, null, null);
    }

    public function timing(string $name, int $millis): bool
    {
        if ($this->usable) {
            $rc = $this->ffi->fossh_timing($this->ctx, $name, $millis);
            return $rc === 0;
        }

        if ($this->remoteEndpoint !== null) {
            $body = ['name' => $name, 'kind' => 'timing', 'value' => $millis];
            return $this->sendHttp('POST', '/e', [], json_encode($body, JSON_THROW_ON_ERROR));
        }

        return $this->fallbackToCgi('/e', ['name' => $name, 'kind' => 'timing', 'value' => (string) $millis], null, null);
    }

    /** Returns the fixed error-name string (e.g. "REJECTED") for the last non-zero return, or null. Only meaningful in FFI mode. */
    public function lastError(): ?string
    {
        if (!$this->usable) {
            return null;
        }
        $buf = \FFI::new('char[64]');
        if ($this->ffi->fossh_last_error($this->ctx, $buf, 64) !== 0) {
            return null;
        }
        // Trimmed at the NUL by hand rather than relying on
        // `FFI::string($buf)`'s one-argument form: for a `char[N]`
        // *array* (as opposed to a `char*`) that form is documented
        // around zero-terminated data, and the C side only writes the
        // message plus its terminator — it does not clear the tail. Two
        // explicit arguments plus this trim give the same answer under
        // either reading, so the binding does not depend on which one a
        // given PHP build implements.
        $raw = \FFI::string($buf, 64);
        $nul = strpos($raw, "\0");
        $message = $nul === false ? $raw : substr($raw, 0, $nul);
        return $message === '' ? null : $message;
    }

    /** Drains any spooled events for this process into the database immediately. Safe to call at shutdown. */
    public function flush(): bool
    {
        if ($this->usable) {
            return $this->ffi->fossh_flush($this->ctx) === 0;
        }
        return true; // nothing buffered in HTTP/CGI-subprocess/no-op mode — each call already completed on its own
    }

    /**
     * HTTP-remote mode: a plain HTTPS call to `$this->remoteEndpoint`,
     * authenticated the same "Bearer mode" way §8 documents for
     * browser-beacon usage where signing is impractical — appropriate
     * here too, since the connection itself is HTTPS and the key never
     * reaches an actual visitor's browser (it stays in this
     * server-side PHP process the whole time).
     *
     * Forwards the *real* visitor's IP/UA (from this script's own
     * `$_SERVER`, not this HTTP client's own connection) via
     * `X-Forwarded-For`/`User-Agent` — the receiving foSSH instance
     * only honors the forwarded IP if its operator explicitly opted in
     * (`FOSSH_TRUST_FORWARDED_FOR=1`; see docs/INTEGRATION-php.md).
     * Without that, every relayed visitor collapses into this
     * server's own egress IP for hashing purposes, which still works,
     * just with degraded per-visitor uniqueness — not a correctness
     * bug in this client, a configuration step on the receiving end.
     *
     * @param array<string,string> $queryParams
     */
    private function sendHttp(string $method, string $path, array $queryParams, ?string $jsonBody): bool
    {
        if ($this->key === null) {
            return false;
        }

        $url = $this->remoteEndpoint . $path;
        if ($queryParams !== []) {
            $url .= '?' . http_build_query($queryParams);
        }

        $headers = ["Authorization: Bearer {$this->key}"];
        if ($jsonBody !== null) {
            $headers[] = 'Content-Type: application/json';
        }
        // Stripped of CR/LF before going anywhere near a raw header
        // line: both come straight from the incoming request
        // ($_SERVER, ultimately the visitor's own browser), so without
        // this an embedded newline could inject an additional,
        // unintended header into this outbound call.
        if (($ua = $_SERVER['HTTP_USER_AGENT'] ?? null) !== null) {
            $headers[] = 'User-Agent: ' . str_replace(["\r", "\n"], '', $ua);
        }
        if (($ip = $_SERVER['REMOTE_ADDR'] ?? null) !== null) {
            $headers[] = 'X-Forwarded-For: ' . str_replace(["\r", "\n"], '', $ip);
        }

        if (\function_exists('curl_init')) {
            return $this->sendViaCurl($method, $url, $headers, $jsonBody);
        }
        if (\filter_var(\ini_get('allow_url_fopen'), FILTER_VALIDATE_BOOLEAN)) {
            return $this->sendViaStreamContext($method, $url, $headers, $jsonBody);
        }
        return false; // neither transport available — still not a fatal error
    }

    /** @param string[] $headers */
    private function sendViaCurl(string $method, string $url, array $headers, ?string $body): bool
    {
        $ch = curl_init($url);
        if ($ch === false) {
            return false;
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT_MS => 1500,
            CURLOPT_TIMEOUT_MS => 2000,
            CURLOPT_HTTPHEADER => $headers,
            // Explicit, though it is also libcurl's default: a 301/302
            // from the endpoint to a plain `http://` URL would otherwise
            // have curl resend the `Authorization: Bearer` header — the
            // write key, in the clear — to wherever the redirect points.
            // The endpoint scheme is vetted at construction; this closes
            // the path that gets around that check after the fact.
            CURLOPT_FOLLOWLOCATION => false,
        ]);
        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body ?? '');
        }
        curl_exec($ch);
        $ok = curl_errno($ch) === 0;
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        // §7.1: the ingest response is always exactly one of
        // 204/401/413/422/429/500, no body — 204 is the only success shape.
        return $ok && $status === 204;
    }

    /** @param string[] $headers */
    private function sendViaStreamContext(string $method, string $url, array $headers, ?string $body): bool
    {
        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headers),
                'content' => $body ?? '',
                'timeout' => 2.0,
                'ignore_errors' => true, // still want $http_response_header on a 4xx/5xx
                // Same reasoning as CURLOPT_FOLLOWLOCATION above, and
                // here it is not the default: PHP's HTTP stream wrapper
                // follows redirects on its own and carries the headers
                // across, so an endpoint that 302s to `http://` would
                // resend the Bearer key in cleartext.
                'follow_location' => 0,
            ],
        ]);
        $result = @file_get_contents($url, false, $context);
        if ($result === false) {
            return false;
        }
        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d+)#', $line, $m) === 1) {
                return ((int) $m[1]) === 204;
            }
        }
        return false;
    }

    /**
     * Best-effort fallback when neither FFI nor HTTP-remote mode is
     * usable: spawn the CGI binary as a one-shot subprocess with the
     * right RFC 3875 environment. If nothing is configured at all,
     * this is a documented no-op — never throws, so a misconfigured or
     * missing telemetry setup can't take the host application down
     * with it.
     *
     * @param array<string,string> $params
     */
    private function fallbackToCgi(string $path, array $params, ?string $ip, ?string $ua): bool
    {
        if ($this->cgiBinaryPath === null) {
            return true; // documented no-op
        }
        $env = [
            'REQUEST_METHOD' => 'GET',
            'PATH_INFO' => $path,
            'QUERY_STRING' => http_build_query($params),
            'REMOTE_ADDR' => $ip ?? ($_SERVER['REMOTE_ADDR'] ?? ''),
            'HTTP_USER_AGENT' => $ua ?? ($_SERVER['HTTP_USER_AGENT'] ?? ''),
        ];
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        // Array form, so PHP execs the binary directly instead of
        // handing the string to `/bin/sh -c`. Two things follow from
        // that, both of which this needs. The path never gets a shell
        // parse, so a space or a metacharacter in it is a path and not
        // syntax. And the process this holds a handle to is fossh-cgi
        // itself rather than a shell wrapping it — which is what makes
        // the timeout below able to actually stop it. Through a shell,
        // terminating the child kills only the shell and leaves the
        // real binary running, orphaned; that is not theoretical, it is
        // what this binding did before and what its own timeout test
        // showed still alive afterwards.
        $process = @proc_open([$this->cgiBinaryPath], $descriptors, $pipes, null, $env);
        if (!\is_resource($process)) {
            return false;
        }
        fclose($pipes[1]);
        fclose($pipes[2]);

        // Bounded rather than a bare proc_close(), which blocks until
        // the child exits with no ceiling. A fossh-cgi that stalls —
        // waiting on a lock, a full disk, an NFS mount that stopped
        // answering — would otherwise hold this PHP request open for as
        // long as the stall lasts, and every concurrent visitor's
        // request with it. Telemetry taking the host site down is the
        // one thing this whole class is arranged to prevent.
        $deadline = microtime(true) + self::CGI_TIMEOUT_SECS;
        $delayUs = 200;
        while (true) {
            $status = proc_get_status($process);
            if ($status === false || !$status['running']) {
                proc_close($process);
                return true;
            }
            if (microtime(true) >= $deadline) {
                proc_terminate($process, 9);
                proc_close($process);
                return false;
            }
            usleep($delayUs);
            // Backs off so a slow-but-healthy child is not polled
            // thousands of times, while a fast one still returns in
            // well under a millisecond.
            $delayUs = min($delayUs * 2, 20000);
        }
    }
}
