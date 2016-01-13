<?php

namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{

    /**
     * Create a new refresh token_name
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface $refreshTokenEntityInterface
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntityInterface)
    {
        // TODO: Implement persistNewRefreshToken() method.
    }

    /**
     * Revoke the refresh token
     *
     * @param string $tokenId
     */
    public function revokeRefreshToken($tokenId)
    {
        // TODO: Implement revokeRefreshToken() method.
    }

    /**
     * Check if the refresh token has been revoked
     *
     * @param string $tokenId
     *
     * @return bool Return true if this token has been revoked
     */
    public function isRefreshTokenRevoked($tokenId)
    {
        // TODO: Implement isRefreshTokenRevoked() method.
    }
}
