<?php

declare(strict_types=1);

namespace League\OAuth2\Server\EventEmitting;

use League\Event\ListenerRegistry;
use Psr\EventDispatcher\EventDispatcherInterface;

trait EmitterAwarePolyfill
{
    private EventEmitter $emitter;

    public function getEmitter(): EventEmitter
    {
        return $this->emitter ??= new EventEmitter();
    }

    public function setEmitter(EventEmitter $emitter): self
    {
        $this->emitter = $emitter;

        return $this;
    }

    public function getEventDispatcher(): EventDispatcherInterface
    {
        return $this->getEmitter();
    }

    public function getListenerRegistry(): ListenerRegistry
    {
        return $this->getEmitter();
    }
}
