<?php

declare(strict_types=1);

namespace League\OAuth2\Server\EventEmitting;

use League\Event\EventDispatcher;
use League\Event\ListenerPriority;

final class EventEmitter extends EventDispatcher
{
    public function addListener(string $event, callable $listener, int $priority = ListenerPriority::NORMAL): self
    {
        $this->subscribeTo($event, $listener, $priority);

        return $this;
    }

    public function emit(object $event): object
    {
        return $this->dispatch($event);
    }
}
