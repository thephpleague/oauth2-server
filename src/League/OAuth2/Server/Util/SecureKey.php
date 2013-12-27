<?php
/**
 * OAuth 2.0 Secure key generator
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Util;

use League\OAuth2\Server\Exception\RuntimeException;

/**
 * SecureKey class
 */
class SecureKey
{
    /**
     * Generate a new unique code
     *
     * @param  int $length Length of the generated code
     * @return string
     * @throws RuntimeException If the secure key cannot be created
     */
    public static function make($length = 40)
    {
        // We generate twice as many bytes here because we want to ensure we have
        // enough after we base64 encode it to get the length we need because we
        // take out the "/", "+", and "=" characters.
        $bytes = openssl_random_pseudo_bytes($length * 2, $strong);

        // We want to stop execution if the key fails because, well, that is bad.
        if ($bytes === false || $strong === false) {
            throw new RuntimeException('Failed to create the secure key');
        }

        return substr(str_replace(array('/', '+', '='), '', base64_encode($bytes)), 0, $length);
    }
}
