<?php

declare(strict_types=1);

require __DIR__ . '/../src/Client.php';

use FoSSH\Client;

final class T
{
    public static int $pass = 0;
    public static int $fail = 0;

    public static function is(mixed $got, mixed $want, string $what): void
    {
        if ($got === $want) {
            self::$pass++;
            printf("  ok   %s\n", $what);
            return;
        }
        self::$fail++;
        printf("  FAIL %s\n       expected %s\n       got      %s\n",
            $what, var_export($want, true), var_export($got, true));
    }

    public static function section(string $name): void
    {
        printf("\n%s\n", $name);
    }

    public static function call(string $method, mixed ...$args): mixed
    {
        $m = new ReflectionMethod(Client::class, $method);
        $m->setAccessible(true);
        return $m->invoke($m->isStatic() ? null : new Client(null, 'k', null, null), ...$args);
    }
}

T::section('Endpoint vetting — the write key is a Bearer token on every request');

$vet = static function (?string $url): ?string {
    $warned = null;
    set_error_handler(static function ($n, $s) use (&$warned) { $warned = $s; return true; });
    $out = T::call('vetEndpoint', $url);
    restore_error_handler();
    return $out;
};

foreach ([
    'https://analytics.example.com',
    'https://example.com:8443/sub/path',
    'http://127.0.0.1:8080',
    'http://127.5.5.5',
    'http://localhost:3000',
    'http://[::1]:8080',
] as $ok) {
    T::is($vet($ok), $ok, "kept: $ok");
}

foreach ([
    'http://analytics.example.com' => 'plain http to a remote host',
    'HTTP://Analytics.Example.com' => 'scheme case does not evade the check',
    'http://evil.tld/?x=127.0.0.1' => 'a loopback address in the query is not the host',

    'http://127.0.0.1.evil.tld'    => 'a hostname that merely starts with 127.',
    'http://127.0.0.1.evil.tld:80' => 'the same, with a port',
    'http://0x7f000001'            => 'hex-encoded loopback is not an IP literal',
    'http://2130706433'            => 'decimal-encoded loopback is not an IP literal',
    'http://[::ffff:127.0.0.1]'    => 'v4-mapped v6 loopback is not ::1',
    'http://169.254.169.254'       => 'link-local metadata is not loopback',
    'ftp://example.com'            => 'a scheme this client does not speak',
    'example.com'                  => 'no scheme at all',
] as $bad => $why) {
    T::is($vet($bad), null, "rejected ($why): $bad");
}
T::is($vet(null), null, 'no endpoint configured stays null');

T::section('Key resolution — FOSSH_KEY must reach the FFI context');

putenv('FOSSH_KEY=from-the-environment');
$c = new Client(null, null, null, null);
$k = new ReflectionProperty(Client::class, 'key');
$k->setAccessible(true);
T::is($k->getValue($c), 'from-the-environment', 'FOSSH_KEY is picked up when no key is passed');

$c = new Client(null, 'explicit', null, null);
T::is($k->getValue($c), 'explicit', 'an explicit key still wins over the environment');
putenv('FOSSH_KEY');

T::section('CGI fallback stays bounded');

$dir = sys_get_temp_dir() . '/fossh-phptest-' . getmypid();
@mkdir($dir, 0700, true);
$hang = "$dir/fosshhang.c";
$bin = "$dir/fosshhang";
file_put_contents($hang, "#include <unistd.h>\nint main(void){for(;;)pause();}\n");
exec('cc -o ' . escapeshellarg($bin) . ' ' . escapeshellarg($hang) . ' 2>/dev/null', $_, $rc);

if ($rc !== 0) {
    printf("  skip cgi timeout (no C compiler available to build a hanging stand-in)\n");
} else {
    $c = new Client(null, 'k', $bin, null);
    $m = new ReflectionMethod(Client::class, 'fallbackToCgi');
    $m->setAccessible(true);
    $started = microtime(true);
    $got = $m->invoke($c, '/e.gif', ['name' => 'pageview'], '1.2.3.4', 'ua');
    $elapsed = microtime(true) - $started;

    T::is($got, false, 'a subprocess that never exits reports failure rather than hanging');
    T::is($elapsed < 5.0, true, sprintf('returned in %.2fs, under the 5s ceiling', $elapsed));

    exec('pgrep -x ' . escapeshellarg(basename($bin)) . ' 2>/dev/null', $alive);
    T::is($alive, [], 'the subprocess itself was killed, not just a shell wrapping it');
    @unlink($bin);
}
@unlink($hang);
@rmdir($dir);

T::section('Redirects are not followed (a 302 to http:// must not resend the key)');

$key = 'WRITE-KEY-SECRET-' . bin2hex(random_bytes(4));
$log = tempnam(sys_get_temp_dir(), 'fosshredir');
$router = tempnam(sys_get_temp_dir(), 'fosshrouter') . '.php';
file_put_contents($router, <<<'ROUTER'
<?php
$log = getenv('FOSSH_TEST_LOG');
$auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (($_SERVER['SERVER_PORT'] ?? '') === getenv('FOSSH_TEST_HOP')) {

    file_put_contents($log, "LEAKED:$auth\n", FILE_APPEND);
    http_response_code(204);
    return true;
}
header('Location: http://127.0.0.1:' . getenv('FOSSH_TEST_HOP') . '/e.gif', true, 302);
return true;
ROUTER);

$hop = '8788';
$env = 'FOSSH_TEST_LOG=' . escapeshellarg($log) . ' FOSSH_TEST_HOP=' . escapeshellarg($hop);
$s1 = proc_open("$env php -S 127.0.0.1:8787 " . escapeshellarg($router),
    [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $p1);
$s2 = proc_open("$env php -S 127.0.0.1:$hop " . escapeshellarg($router),
    [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']], $p2);
usleep(400000);

$c = new Client(null, $key, null, 'http://127.0.0.1:8787');
$c->pageview();

$send = new ReflectionMethod(Client::class, 'sendViaStreamContext');
$send->setAccessible(true);
$send->invoke($c, 'GET', 'http://127.0.0.1:8787/e.gif', ["Authorization: Bearer {$key}"], null);

usleep(200000);
$leaked = trim((string) @file_get_contents($log));
T::is($leaked, '', 'neither the curl nor the stream transport carried the key across a redirect');

foreach ([[$s1, $p1], [$s2, $p2]] as [$s, $_p]) {
    if (\is_resource($s)) { proc_terminate($s, 9); proc_close($s); }
}
@unlink($log);
@unlink($router);

printf("\n%d passed, %d failed\n", T::$pass, T::$fail);
exit(T::$fail === 0 ? 0 : 1);
