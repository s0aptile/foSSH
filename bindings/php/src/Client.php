<?php

declare(strict_types=1);

namespace FoSSH;

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

    private const CGI_TIMEOUT_SECS = 2.0;

    private ?\FFI $ffi = null;

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
            return;
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

    public function lastError(): ?string
    {
        if (!$this->usable) {
            return null;
        }
        $buf = \FFI::new('char[64]');
        if ($this->ffi->fossh_last_error($this->ctx, $buf, 64) !== 0) {
            return null;
        }

        $raw = \FFI::string($buf, 64);
        $nul = strpos($raw, "\0");
        $message = $nul === false ? $raw : substr($raw, 0, $nul);
        return $message === '' ? null : $message;
    }

    public function flush(): bool
    {
        if ($this->usable) {
            return $this->ffi->fossh_flush($this->ctx) === 0;
        }
        return true;
    }

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
        return false;
    }

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

        return $ok && $status === 204;
    }

    private function sendViaStreamContext(string $method, string $url, array $headers, ?string $body): bool
    {
        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headers),
                'content' => $body ?? '',
                'timeout' => 2.0,
                'ignore_errors' => true,

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

    private function fallbackToCgi(string $path, array $params, ?string $ip, ?string $ua): bool
    {
        if ($this->cgiBinaryPath === null) {
            return true;
        }
        $env = [
            'REQUEST_METHOD' => 'GET',
            'PATH_INFO' => $path,
            'QUERY_STRING' => http_build_query($params),
            'REMOTE_ADDR' => $ip ?? ($_SERVER['REMOTE_ADDR'] ?? ''),
            'HTTP_USER_AGENT' => $ua ?? ($_SERVER['HTTP_USER_AGENT'] ?? ''),
        ];
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];

        $process = @proc_open([$this->cgiBinaryPath], $descriptors, $pipes, null, $env);
        if (!\is_resource($process)) {
            return false;
        }
        fclose($pipes[1]);
        fclose($pipes[2]);

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

            $delayUs = min($delayUs * 2, 20000);
        }
    }
}
