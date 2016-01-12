<?php
/**
 * OAuth 2.0 Access token storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;

/**
 * Access token interface
 */
interface AccessTokenRepositoryInterface extends RepositoryInterface
{
    /**
     * Persists a new access token to permanent storage
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface $accessTokenEntity
     */
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity);

    /**
     * Revoke an access token
     *
     * @param string $tokenId
     */
    public function revokeAccessToken($tokenId);

    /**
     * Check if the access token has been revoked
     *
     * @param string $tokenId
     *
     * @return bool Return true if this token has been revoked
     */
    public function isAccessTokenRevoked($tokenId);
}
