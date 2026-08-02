<?php

declare(strict_types=1);

namespace FoSSH\Symfony;

use FoSSH\Client;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Records a Pageview for every main (non-sub) request. Register as a
 * normal service and tag `kernel.event_subscriber` (autoconfiguration
 * picks this up automatically in a standard Symfony app, since this
 * class implements `EventSubscriberInterface`).
 *
 * Requires `symfony/http-kernel` and `symfony/event-dispatcher` —
 * intentionally not in this package's own `composer.json` `require`,
 * since most consumers of the core `FoSSH\Client` aren't running
 * Symfony at all. Only autoloaded (and so only needs those two
 * packages present) if your app actually references this class.
 */
final class FosshRequestSubscriber implements EventSubscriberInterface
{
    public function __construct(private readonly Client $fossh)
    {
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::REQUEST => 'onKernelRequest'];
    }

    public function onKernelRequest(RequestEvent $event): void
    {
        if ($event->isMainRequest()) {
            $this->fossh->pageview();
        }
    }
}
