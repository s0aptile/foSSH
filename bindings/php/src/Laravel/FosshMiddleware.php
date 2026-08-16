<?php

declare(strict_types=1);

namespace FoSSH\Laravel;

use Closure;
use FoSSH\Client;

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
