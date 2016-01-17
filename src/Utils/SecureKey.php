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

namespace League\OAuth2\Server\Utils;

use League\OAuth2\Server\Exception\OAuthServerException;


/**
 * SecureKey class
 */
class SecureKey
{
    /**
     * Generate a new unique code
     *
     * @param integer $len Length of the generated code
     *
     * @return string
     * @throws \League\OAuth2\Server\Exception\OAuthServerException
     */
    public static function generate($len = 40)
    {
        try {
            $string = random_bytes($len);
        } catch (\TypeError $e) {
            // Well, it's an integer, so this IS unexpected.
            throw OAuthServerException::serverError("An unexpected error has occurred");
        } catch (\Error $e) {
            // This is also unexpected because 32 is a reasonable integer.
            throw OAuthServerException::serverError("An unexpected error has occurred");
        } catch (\Exception $e) {
            // If you get this message, the CSPRNG failed hard.
            throw OAuthServerException::serverError("Could not generate a random string. Is our OS secure?");
        }

        return bin2hex($string);
    }
}
