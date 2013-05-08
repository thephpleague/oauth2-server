<?php
/**
 * OAuth 2.0 Redirect URI generator
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Util;

/**
 * RedirectUri class
 */
class RedirectUri
{
	/**
	 * Generate a new redirect uri
	 * @param  string $uri            The base URI
	 * @param  array  $params         The query string parameters
	 * @param  string $queryDelimeter The query string delimeter (default: "?")
	 * @return string                 The updated URI
	 */
    public static function make($uri, $params = array(), $queryDelimeter = '?')
    {
        $uri .= (strstr($uri, $queryDelimeter) === false) ? $queryDelimeter : '&';
        return $uri.http_build_query($params);
    }
}