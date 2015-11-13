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
     * Return a new instance of \League\OAuth2\Server\Entity\RefreshTokenEntity
     *
     * @param string $token Refresh token string
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface
     */
    public function getRefreshTokenEntityByTokenString($token);

    /**
     * Create a new refresh token_name
     *
     * @param string  $token
     * @param integer $expireTime
     * @param string  $accessToken
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface
     */
    public function persistNewRefreshTokenEntity($token, $expireTime, $accessToken);

    /**
     * Delete the refresh token
     *
     * @param \League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface $token
     */
    public function deleteRefreshTokenEntity(RefreshTokenEntityInterface $token);
}
