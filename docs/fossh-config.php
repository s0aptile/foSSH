<?php

declare(strict_types=1);

if (!defined('FOSSH_KEY')) {
    define('FOSSH_KEY', '');
}

if (!defined('FOSSH_ENDPOINT')) {
    define('FOSSH_ENDPOINT', '');
}

if (!defined('FOSSH_GPRODUCTS')) {
    define('FOSSH_GPRODUCTS', 'f');
}

if (!function_exists('fossh_strip_header_injection')) {

    function fossh_strip_header_injection(?string $value): ?string
    {
        if ($value === null) {
            return null;
        }
        return str_replace(["\r", "\n"], '', $value);
    }
}

if (!function_exists('fossh_send')) {

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

                        'follow_location' => 0,
                    ],
                ]);
                @file_get_contents($url, false, $context);
            }

        } catch (\Throwable $e) {

        }
    }
}

(function (): void {
    if (FOSSH_KEY === '' || FOSSH_ENDPOINT === '') {
        return;
    }

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

        $headers[] = 'X-Forwarded-For: ' . $visitorIp;
    }

    fossh_send($url, $headers);
})();
