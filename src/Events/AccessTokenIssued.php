<?php

namespace League\OAuth2\Server\Events;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use Psr\Http\Message\ServerRequestInterface;

final class AccessTokenIssued extends AbstractEvent
{
    /** @var AccessTokenEntityInterface */
    private $accessToken;

    public function __construct(
        AccessTokenEntityInterface $accessToken,
        ServerRequestInterface $request
    ) {
        parent::__construct($request);
        $this->name = 'access_token.issued';
        $this->accessToken = $accessToken;
    }

    public function getAccessToken(): AccessTokenEntityInterface
    {
        return $this->accessToken;
    }
}
