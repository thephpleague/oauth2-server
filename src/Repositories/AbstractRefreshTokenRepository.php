<?php
/**
 * OAuth 2.0 Refresh token storage abstract class.
 *
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntity;

/**
 * Refresh token abstract class.
 */
abstract class AbstractRefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    /**
     * Creates a new refresh token
     *
     * @return RefreshTokenEntityInterface
     */
    public function getNewRefreshToken()
    {
        return new RefreshTokenEntity();
    }

    /**
     * Create a new refresh token_name.
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface $refreshTokenEntity
     */
    abstract public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity);

    /**
     * Revoke the refresh token.
     *
     * @param string $tokenId
     */
    abstract public function revokeRefreshToken($tokenId);

    /**
     * Check if the refresh token has been revoked.
     *
     * @param string $tokenId
     *
     * @return bool Return true if this token has been revoked
     */
    abstract public function isRefreshTokenRevoked($tokenId);
}
