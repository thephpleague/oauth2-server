<?php

namespace League\OAuth2\Server\Events;

use Psr\Http\Message\ServerRequestInterface;

abstract class AbstractRequestEvent
{
    /**
     * @var ServerRequestInterface
     */
    private $request;

    /**
     * AbstractRequestEvent constructor.
     *
     * @param ServerRequestInterface $request
     */
    public function __construct(ServerRequestInterface $request)
    {
        $this->request = $request;
    }

    /**
     * @return ServerRequestInterface
     * @codeCoverageIgnore
     */
    public function getRequest()
    {
        return $this->request;
    }
}
