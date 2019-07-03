<?php

/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Event;

use Psr\EventDispatcher\StoppableEventInterface;
use Psr\Http\Message\ServerRequestInterface;

class RequestEvent implements StoppableEventInterface
{
    /**
     * @var ServerRequestInterface
     */
    private $request;

    /**
     * @var bool
     */
    protected $isPropagationStopped = false;

    /**
     * RequestEvent constructor.
     *
     * @param ServerRequestInterface $request
     */
    public function __construct(ServerRequestInterface $request)
    {
        $this->request = $request;
    }

    public function stopPropagation()
    {
        $this->isPropagationStopped = true;
    }

    public function isPropagationStopped(): bool
    {
        return $this->isPropagationStopped;
    }

    /**
     * @return ServerRequestInterface
     * @codeCoverageIgnore
     */
    public function getRequest()
    {
        return $this->request;
    }

    public static function clientAuthenticationFailed(ServerRequestInterface $request): self
    {
        return new ClientAuthenticationFailedEvent($request);
    }

    public static function accessTokenIssued(ServerRequestInterface $request): self
    {
        return new AccessTokenIssuedEvent($request);
    }

    public static function userAuthenticationFailed(ServerRequestInterface $request): self
    {
        return new UserAuthenticationFailedEvent($request);
    }

    public static function refreshTokenIssued(ServerRequestInterface $request): self
    {
        return new RefreshTokenIssuedEvent($request);
    }

    public static function refreshTokenClientFailed(ServerRequestInterface $request): self
    {
        return new RefreshTokenClientFailedEvent($request);
    }
}
