<?php

namespace League\OAuth2\Server\Event;

use Psr\EventDispatcher\EventDispatcherInterface;

class DummyEventDispatcher implements EventDispatcherInterface
{

    public function dispatch(object $event): object
    {
        return $event;
    }

}
