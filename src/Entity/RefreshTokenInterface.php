<?php
/**
 * OAuth 2.0 Refresh token interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entity;

/**
 * Refresh token entity interface
 */
interface RefreshTokenInterface extends TokenInterface
{
    /**
     * Set the ID of the associated access token
     * @param  string $accessTokenId
     * @return self
     */
    public function setAccessTokenId($accessTokenId);

    /**
     * Associate an access token
     * @param  \League\OAuth2\Server\Entity\AccessTokenInterface $accessTokenEntity
     * @return self
     */
    public function setAccessToken(AccessTokenInterface $accessTokenEntity);

    /**
     * Return access token
     * @return AccessTokenEntity
     */
    public function getAccessToken();
}
