<?php

namespace League\OAuth2\Server\Events;

use Psr\Http\Message\ServerRequestInterface;

abstract class AbstractEvent
{
    /** @var string */
    protected $name;

    /** @var ServerRequestInterface */
    protected $request;

    /** @var \DateTimeImmutable */
    protected $occuredOn;

    public function __construct(ServerRequestInterface $request)
    {
        $this->name = static::class;
        $this->request = $request;
        $this->occuredOn = new \DateTimeImmutable();
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getRequest(): ServerRequestInterface
    {
        return $this->request;
    }

    public function getOccuredOn(): \DateTimeImmutable
    {
        return $this->occuredOn;
    }
}
