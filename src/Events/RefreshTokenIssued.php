<?php

namespace League\OAuth2\Server\Events;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use Psr\Http\Message\ServerRequestInterface;

final class RefreshTokenIssued extends AbstractEvent
{
    /** @var RefreshTokenEntityInterface */
    private $refreshToken;

    public function __construct(
        RefreshTokenEntityInterface $refreshToken,
        ServerRequestInterface $request
    ) {
        parent::__construct($request);
        $this->name = 'refresh_token.issued';
        $this->refreshToken = $refreshToken;
    }

    public function getRefreshToken(): RefreshTokenEntityInterface
    {
        return $this->refreshToken;
    }
}
