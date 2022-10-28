<?php
declare(strict_types=1);

namespace League\OAuth2\Server\EventEmitting;

use League\Event\ListenerRegistry;
use Psr\EventDispatcher\EventDispatcherInterface;

trait EmitterAwarePolyfill
{
    /**
     * @var EventEmitter
     */
    private $emitter;

    public function getEmitter(): EventEmitter
    {
        if (!$this->emitter) {
            $this->emitter = new EventEmitter();
        }

        return $this->emitter;
    }

    /**
     * @return $this
     */
    public function setEmitter(EventEmitter $emitter)
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
