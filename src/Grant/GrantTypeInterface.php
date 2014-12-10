<?php
/**
 * OAuth 2.0 Grant type interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\AuthorizationServer;

/**
 * Grant type interface
 */
interface GrantTypeInterface
{
    /**
     * Return the identifier
     *
     * @return string
     */
    public function getIdentifier();

    /**
     * Return the identifier
     *
     * @param string $identifier
     *
     * @return self
     */
    public function setIdentifier($identifier);

    /**
     * Return the response type
     *
     * @return string
     */
    public function getResponseType();

    /**
     * Inject the authorization server into the grant
     *
     * @param \League\OAuth2\Server\AuthorizationServer $server The authorization server instance
     *
     * @return self
     */
    public function setAuthorizationServer(AuthorizationServer $server);

    /**
     * Complete the grant flow
     *
     * @return array
     */
    public function completeFlow();
}
