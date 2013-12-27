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
 * Interface for auth code service
 */
interface AuthCodeServiceInterface
{
    /**
     * @param  string $code
     * @return mixed
     */
    public function getCode($code);
}
