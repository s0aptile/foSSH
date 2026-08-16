<?php

declare(strict_types=1);

namespace FoSSH\Symfony;

use FoSSH\Client;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

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
