<?php
/**
 * OAuth 2.0 Grant type interface
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

/**
 * Interface that all grant type must implement
 *
 * This library comes with pre-defined implementation for flows defined in the specification, but
 * you can define your own
 */
interface GrantTypeInterface
{
    /**
     * Complete the grant flow
     *
     * Example response:
     * <code>
     * 	[
     *  	'access_token'  =>  (string),	// The access token
     *      'refresh_token' =>  (string),	// The refresh token (only set if the refresh token grant is enabled)
     *      'token_type'    =>  'bearer',	// Almost always "bearer" (exceptions: JWT, SAML)
     *      'expires'       =>  (int),		// The timestamp of when the access token will expire
     *      'expires_in'    =>  (int)		// The number of seconds before the access token will expire
     *  ]
     * </code>
     *
     * @return array An array of parameters to be passed back to the client
     */
    public function completeFlow();
}
