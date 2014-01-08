<?php
/**
 * OAuth 2.0 storage adapter
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Storage;

/**
 * Storage adapter class
 */
class Adapter
{
    /**
     * Server
     * @var \League\OAuth2\Server\Authorization|\League\OAuth2\Server\Resource $server
     */
    protected $server;

    /**
     * Set the server
     * @param \League\OAuth2\Server\Authorization|\League\OAuth2\Server\Resource $server
     */
    public function setServer($server)
    {
        $this->server = $server;
        return $this;
    }

    /**
     * Return the server
     * @return \League\OAuth2\Server\Authorization|\League\OAuth2\Server\Resource
     */
    protected function getServer()
    {
        return $this->server;
    }
}
