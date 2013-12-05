<?php
/**
 * OAuth 2.0 Client credentials grant
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Authorization;

trait GrantTrait {

    /**
     * Constructor
     * @param Authorization $authServer Authorization server instance
     * @return void
     */
    public function __construct(Authorization $authServer = null)
    {
        // @codeCoverageIgnoreStart
        if ($authServer instanceof Authorization) {
            trigger_error(
                'Server is now automatically injected into grant as of v3.1 of this library',
                E_USER_DEPRECATED
            );
        } // @codeCoverageIgnoreEnd
    }

    /**
     * Return the identifier
     * @return string
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * Return the identifier
     * @param string $identifier
     * @return self
     */
    public function setIdentifier($identifier)
    {
        $this->identifier = $identifier;
        return $this;
    }

    /**
     * Return the response type
     * @return string
     */
    public function getResponseType()
    {
        return $this->responseType;
    }

    /**
     * Override the default access token expire time
     * @param int $accessTokenTTL
     * @return self
     */
    public function setAccessTokenTTL($accessTokenTTL)
    {
        $this->accessTokenTTL = $accessTokenTTL;
        return $this;
    }

    /**
     * Inject the authorization server into the grant
     * @param Authorization $authServer The authorization server instance
     * @return  self
     */
    public function setAuthorizationServer(Authorization $authServer)
    {
        $this->authServer = $authServer;
        return $this;
    }

}
