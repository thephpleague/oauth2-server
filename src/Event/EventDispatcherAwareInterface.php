<?php

namespace League\OAuth2\Server\Event;

use Psr\EventDispatcher\EventDispatcherInterface;

interface EventDispatcherAwareInterface
{

    /**
     * Set the Emitter.
     *
     * @param EventDispatcherInterface $emitter
     *
     * @return $this
     */
    public function setEventDispatcher(EventDispatcherInterface $emitter = null);

    /**
     * Get the Emitter.
     *
     * @return EventDispatcherInterface
     */
    public function getEventDispatcher();
}
