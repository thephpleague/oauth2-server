<?php

/**
 * OAuth 2.0 Refresh token storage interface
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Storage;

/**
 * Service interface for refresh tokens
 */
interface RefreshTokenServiceInterface
{
    /**
     * Get a refresh token
     *
     * @param  string $token
     * @param  string $clientId
     * @return mixed
     */
    public function getToken($token, $clientId);
}
