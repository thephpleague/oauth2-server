<?php

namespace League\OAuth2\Server\Events;

use Psr\EventDispatcher\EventDispatcherInterface;

trait EventDispatchableTrait
{
    /** @var EventDispatcherInterface|null */
    protected $eventDispatcher;

    public function useEventDispatcher(?EventDispatcherInterface $eventDispatcher): void
    {
        $this->eventDispatcher = $eventDispatcher;
    }

    public function dispatchEvent(object $event): object
    {
        if ($this->eventDispatcher !== null) {
            return $this->eventDispatcher->dispatch($event);
        }

        return $event;
    }
}