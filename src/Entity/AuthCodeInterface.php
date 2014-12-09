<?php
/**
 * OAuth 2.0 Auth code entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entity;

interface AuthCodeInterface extends TokenInterface
{
    /**
     * Set the redirect URI for the authorization request
     * @param  string $redirectUri
     * @return self
     */
    public function setRedirectUri($redirectUri);

    /**
     * Get the redirect URI
     * @return string
     */
    public function getRedirectUri();

    /**
     * Generate a redirect URI
     * @param  string $state          The state parameter if set by the client
     * @param  string $queryDelimeter The query delimiter ('?' for auth code grant, '#' for implicit grant)
     * @return string
     */
    public function generateRedirectUri($state = null, $queryDelimeter = '?');

    /**
     * Get session
     * @return SessionEntity
     */
    public function getSession();

    /**
     * Return all scopes associated with the session
     * @return ScopeEntity[]
     */
    public function getScopes();
}
