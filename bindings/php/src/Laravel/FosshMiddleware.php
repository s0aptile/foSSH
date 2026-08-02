<?php

declare(strict_types=1);

namespace FoSSH\Laravel;

use Closure;
use FoSSH\Client;

/**
 * Records a Pageview for every request that passes through this
 * middleware. Register it globally in `bootstrap/app.php` (Laravel
 * 11+) or `app/Http/Kernel.php`'s `$middleware` array (older
 * versions), or attach it to a specific route group if you only want
 * it on some routes.
 *
 * A recording failure never turns into an HTTP error response for the
 * request it's observing — `Client::pageview()` already never throws
 * (see its own implementation), so nothing extra is needed here to
 * keep this middleware from being able to break the app.
 */
final class FosshMiddleware
{
    public function __construct(private readonly Client $fossh)
    {
    }

    public function handle($request, Closure $next)
    {
        $this->fossh->pageview();

        return $next($request);
    }
}
