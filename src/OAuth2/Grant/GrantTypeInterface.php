<?php
/**
 * OAuth 2.0 Grant type interface
 *
 * @package     lncd/oauth2
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 University of Lincoln
 * @license     http://mit-license.org/
 * @link        http://github.com/lncd/oauth2
 */

namespace OAuth2\Grant;

use OAuth2\Request;
use OAuth2\AuthServer;
use OAuth2\Exception;
use OAuth2\Util\SecureKey;
use OAuth2\Storage\SessionInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\Storage\ScopeInterface;

interface GrantTypeInterface
{
	/**
	 * Returns the grant identifier (used to validate grant_type in OAuth2\AuthServer\issueAccessToken())
	 * @return string
	 */
    public function getIdentifier();

    /**
     * Returns the response type (used to validate response_type in OAuth2\AuthServer\checkAuthoriseParams())
     * @return null|string
     */
    public function getResponseType();

    /**
     * Complete the grant flow
     *
     * Example response:
     * <code>
     * 	array(
     *  	'access_token'  =>  (string),	// The access token
     *      'refresh_token' =>  (string),	// The refresh token (only set if the refresh token grant is enabled)
     *      'token_type'    =>  'bearer',	// Almost always "bearer" (exceptions: JWT, SAML)
     *      'expires'       =>  (int),		// The timestamp of when the access token will expire
     *      'expires_in'    =>  (int)		// The number of seconds before the access token will expire
     *  )
     * </code>
     *
     * @param  null|array $inputParams Null unless the input parameters have been manually set
     * @return array                   An array of parameters to be passed back to the client
     */
    public function completeFlow($inputParams = null);
}
