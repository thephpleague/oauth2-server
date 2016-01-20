<?php
/**
 * OAuth 2.0 Refresh token storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface;

/**
 * Refresh token interface
 */
interface RefreshTokenRepositoryInterface extends RepositoryInterface
{
    /**
     * Create a new refresh token_name
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface $refreshTokenEntity
     */
    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity);

    /**
     * Revoke the refresh token
     *
     * @param string $tokenId
     */
    public function revokeRefreshToken($tokenId);

    /**
     * Check if the refresh token has been revoked
     *
     * @param string $tokenId
     *
     * @return bool Return true if this token has been revoked
     */
    public function isRefreshTokenRevoked($tokenId);
}
