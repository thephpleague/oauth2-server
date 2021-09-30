<?php

namespace League\OAuth2\Server\Events;

use Psr\EventDispatcher\EventDispatcherInterface;

interface EventDispatcherAwareInterface
{
    public function useEventDispatcher(?EventDispatcherInterface $dispatcher): void;
}
