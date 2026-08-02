<?php

// Runnable example for the PHP binding (bindings/php). Serve with:
//   php -S localhost:8080 index.php
// Set FOSSH_ENDPOINT + FOSSH_KEY for the shared-hosting HTTP-remote
// transport (see docs/INTEGRATION-php.md), or FOSSH_LIB_PATH if
// ext-ffi and libfossh.so are both available locally.

declare(strict_types=1);

require_once __DIR__ . '/../../bindings/php/src/Client.php';

$fossh = new \FoSSH\Client(
    configPath: getenv('FOSSH_CONFIG') ?: null,
    key: getenv('FOSSH_KEY') ?: null,
    remoteEndpoint: getenv('FOSSH_ENDPOINT') ?: null,
);
register_shutdown_function(fn () => $fossh->flush());

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

if ($path === '/signup') {
    $fossh->event('signup', 1, ['plan' => 'pro']);
    echo "signed up\n";
    return;
}

$fossh->pageview();
echo "hello from an app with foSSH wired in\n";
