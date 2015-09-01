<?php
/**
 * OAuth 2.0 abstract storage
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Storage;

use League\OAuth2\Server\ServerInterface\Server;

/**
 * Abstract storage class
 */
abstract class AbstractStorage implements StorageInterface
{
    /**
     * Server
     *
     * @var Server $server
     */
    protected $server;

    /**
     * Set the server
     *
     *
     * @param Server $server
     *
     * @return AbstractStorage
     */
    public function setServer(Server $server)
    {
        $this->server = $server;

        return $this;
    }

    /**
     * Return the server
     *
     * @return Server
     *
     */
    protected function getServer()
    {
        return $this->server;
    }
}
