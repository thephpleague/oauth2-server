<?php
/**
 * OAuth 2.0 Refresh token storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Storage;

/**
 * Refresh token interface
 */
interface RefreshTokenInterface
{
    /**
     * Return a new instance of \League\OAuth2\Server\Entity\RefreshToken
     * @param  string $token
     * @return \League\OAuth2\Server\Entity\RefreshToken
     */
    public function get($token);

    /**
     * Create a new refresh token_name
     * @param  string $token
     * @param  integer $expireTime
     * @param  string $accessToken
     * @return \League\OAuth2\Server\Entity\RefreshToken
     */
    public function create($token, $expireTime, $accessToken);

    /**
     * Delete the refresh token
     * @param  string $token
     * @return void
     */
    public function delete($token);
}
