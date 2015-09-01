<?php


namespace League\OAuth2\Server\ServerInterface;


interface EventDispatcher {
    /**
     * Set an event emitter
     *
     * @param object $emitter Event emitter object
     */
    public function setEventEmitter($emitter);
    /**
     * Add an event listener to the event emitter
     *
     * @param string   $eventName Event name
     * @param callable $listener  Callable function or method
     */
    public function addEventListener($eventName, callable $listener);

    /**
     * Returns the event emitter
     *
     * @return \League\Event\Emitter
     */
    public function getEventEmitter();
}