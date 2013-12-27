<?php

/**
 * OAuth 2.0 Access token storage interface
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Storage;

/**
 * Interface for access token service
 */
interface AccessTokenInterface
{
    /**
     * @param  string $token
     * @return mixed
     */
    public function getToken($token);

    /**
     * @param  string $token
     * @return array
     */
    public function getTokenScopes($token);

    /**
     * @param  string $token
     * @param  string $expireTime
     * @param  string $sessionId
     * @return mixed
     */
    public function createAccessToken($token, $expireTime, $sessionId);

    /**
     * @param  string $token
     * @param  string $scopeId
     * @return mixed
     */
    public function associateScope($token, $scopeId);
}
