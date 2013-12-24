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

interface AccessTokenInterface
{
    public function getToken($token);

    public function getTokenScopes($token);

    public function createAccessToken($token, $expireTime, $sessionId);

    public function associateScope($token, $scopeId);
}
