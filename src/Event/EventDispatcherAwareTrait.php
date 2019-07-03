<?php

namespace League\OAuth2\Server\Event;

use Psr\EventDispatcher\EventDispatcherInterface;

trait EventDispatcherAwareTrait
{
    /**
     * The evetn dispatcher instance.
     *
     * @var EventDispatcherInterface|null
     */
    protected $eventDispatcher;

    /**
     * Set the Emitter.
     *
     * @param EventDispatcherInterface|null $eventDispatcher
     *
     * @return $this
     */
    public function setEventDispatcher(EventDispatcherInterface $eventDispatcher = null)
    {
        $this->eventDispatcher = $eventDispatcher;

        return $this;
    }

    /**
     * Get the Emitter.
     *
     * @return EmitterInterface
     */
    public function getEventDispatcher()
    {
        if ($this->eventDispatcher instanceof EventDispatcherInterface === false) {
            $this->eventDispatcher = new DummyEventDispatcher();
        }

        return $this->eventDispatcher;
    }
}
