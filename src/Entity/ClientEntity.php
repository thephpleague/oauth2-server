<?php
/**
 * OAuth 2.0 Client entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entity;

use League\OAuth2\Server\AbstractServer;

/**
 * Client entity class
 */
class ClientEntity
{
    /**
     * Client identifier
     * @var string
     */
    protected $id = null;

    /**
     * Client secret
     * @var string
     */
    protected $secret = null;

    /**
     * Client name
     * @var string
     */
    protected $name = null;

    /**
     * Client redirect URI
     * @var string
     */
    protected $redirectUri = null;

    /**
     * Authorization or resource server
     * @var \League\OAuth2\Server\AbstractServer
     */
    protected $server;

    /**
     * __construct
     * @param  \League\OAuth2\Server\AbstractServer $server
     * @return self
     */
    public function __construct(AbstractServer $server)
    {
        $this->server = $server;

        return $this;
    }

    /**
     * Set the client identifier
     * @param  string $id
     * @return self
     */
    public function setId($id)
    {
        $this->id = $id;

        return $this;
    }

    /**
     * Return the client identifier
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Set the client secret
     * @param  string $secret
     * @return self
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }

    /**
     * Return the client secret
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * Set the client name
     * @param  string $name
     * @return self
     */
    public function setName($name)
    {
        $this->name = $name;

        return $this;
    }

    /**
     * Get the client name
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Set the client redirect URI
     * @param  string $redirectUri
     * @return self
     */
    public function setRedirectUri($redirectUri)
    {
        $this->redirectUri = $redirectUri;

        return $this;
    }

    /**
     * Returnt the client redirect URI
     * @return string
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }
}
