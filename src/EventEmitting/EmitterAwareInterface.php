<?php

declare(strict_types=1);

namespace League\OAuth2\Server\EventEmitting;

interface EmitterAwareInterface
{
    public function getEmitter(): EventEmitter;

    public function setEmitter(EventEmitter $emitter): self;
}
