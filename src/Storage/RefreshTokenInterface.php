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

namespace League\OAuth2\Server\Storage;

use League\OAuth2\Server\Entity\RefreshTokenInterface as RefreshTokenEntityInterface;

/**
 * Refresh token interface
 */
interface RefreshTokenInterface extends StorageInterface
{
    /**
     * Return a new instance of \League\OAuth2\Server\Entity\RefreshTokenEntityInterface
     * @param  string                                             $token
     * @return \League\OAuth2\Server\Entity\RefreshTokenInterface
     */
    public function get($token);

    /**
     * Create a new refresh token_name
     * @param  string                                             $token
     * @param  integer                                            $expireTime
     * @param  string                                             $accessToken
     * @return \League\OAuth2\Server\Entity\RefreshTokenInterface
     */
    public function create($token, $expireTime, $accessToken);

    /**
     * Delete the refresh token
     * @param  \League\OAuth2\Server\Entity\RefreshTokenInterface $token
     * @return void
     */
    public function delete(RefreshTokenEntityInterface $token);
}
