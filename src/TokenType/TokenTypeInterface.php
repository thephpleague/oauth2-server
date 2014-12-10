<?php
/**
 * OAuth 2.0 Token Type Interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\TokenType;

use League\OAuth2\Server\AbstractServer;
use League\OAuth2\Server\Entity\SessionEntity;
use Symfony\Component\HttpFoundation\Request;

interface TokenTypeInterface
{
    /**
     * Generate a response
     *
     * @return array
     */
    public function generateResponse();

    /**
     * Set the server
     *
     * @param \League\OAuth2\Server\AbstractServer $server
     *
     * @return self
     */
    public function setServer(AbstractServer $server);

    /**
     * Set a key/value response pair
     *
     * @param string $key
     * @param mixed  $value
     */
    public function setParam($key, $value);

    /**
     * Get a key from the response array
     *
     * @param string $key
     *
     * @return mixed
     */
    public function getParam($key);

    /**
     * @param \League\OAuth2\Server\Entity\SessionEntity $session
     *
     * @return self
     */
    public function setSession(SessionEntity $session);

    /**
     * Determine the access token in the authorization header
     *
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return string
     */
    public function determineAccessTokenInHeader(Request $request);
}
