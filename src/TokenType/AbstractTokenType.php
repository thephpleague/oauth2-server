<?php
/**
 * OAuth 2.0 Abstract Token Type
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

abstract class AbstractTokenType
{
    /**
     * Response array
     * @var array
     */
    protected $response = [];

    /**
     * Server
     * @var \League\OAuth2\Server\AbstractServer $server
     */
    protected $server;

    /**
     * Server
     * @var \League\OAuth2\Server\Entity\SessionEntity $session
     */
    protected $session;

    /**
     * Set the server
     * @param \League\OAuth2\Server\AbstractServer $server
     * @return self
     */
    public function setServer(AbstractServer $server)
    {
        $this->server = $server;

        return $this;
    }

    /**
     * Set the session entity
     * @param \League\OAuth2\Server\Entity\SessionEntity $session
     * @return self
     */
    public function setSession(SessionEntity $session)
    {
        $this->session = $session;

        return $this;
    }

    /**
     * Set a key/value response pair
     * @param string $key
     * @param mixed  $value
     */
    public function setParam($key, $value)
    {
        $this->response[$key] = $value;
    }

    /**
     * Get a key from the response array
     * @param  string $key
     * @return mixed
     */
    public function getParam($key)
    {
        return isset($this->response[$key]) ? $this->response[$key] : null;
    }

    /**
     * Determine the access token in the authorization header
     * @param  \Symfony\Component\HttpFoundation\Request $request
     * @return string
     */
    abstract public function determineAccessTokenInHeader(Request $request);
}
