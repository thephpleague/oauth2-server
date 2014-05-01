<?php
/**
 * OAuth 2.0 Client storage interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Storage;

use League\OAuth2\Server\Entity\Session;

/**
 * Client storage interface
 */
interface ClientInterface
{
    /**
     * Validate a client
     * @param  string     $clientId     The client's ID
     * @param  string     $clientSecret The client's secret (default = "null")
     * @param  string     $redirectUri  The client's redirect URI (default = "null")
     * @param  string     $grantType    The grant type used in the request (default = "null")
     * @return League\OAuth2\Server\Entity\Client
     */
    public function get($clientId, $clientSecret = null, $redirectUri = null, $grantType = null);

    /**
     * Get the client associated with a session
     * @param  \League\OAuth2\Server\Entity\Session $session The session
     * @return \League\OAuth2\Server\Entity\Client
     */
    public function getBySession(Session $session);
}
