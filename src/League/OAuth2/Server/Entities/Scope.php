<?php
/**
 * OAuth 2.0 scope entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\Exception\ServerException;
use League\OAuth2\Server\AbstractServer;

/**
 * Scope entity class
 */
class Scope
{
    /**
     * Scope identifier
     * @var string
     */
    protected $id;

    /**
     * Scope description
     * @var string
     */
    protected $description;

    /**
     * Authorization or resource server
     * @var \League\OAuth2\Server\Authorization|\League\OAuth2\Server\Resource
     */
    protected $server;

    /**
     * __construct
     * @param \League\OAuth2\Server\AbstractServer $server
     * @return self
     */
    public function __construct(AbstractServer $server)
    {
        $this->server = $server;
        return $this;
    }

    /**
     * Set the scope identifer
     * @param string $id The scope identifier
     * @return self
     */
    public function setId($id)
    {
        $this->id = $id;
        return $this;
    }

    /**
     * Return the scope identifer
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Set the scope's descripton
     * @param string $description
     * @return self
     */
    public function setDescription($description)
    {
        $this->description = $description;
        return $this;
    }

    /**
     * Return the scope's description
     * @return string
     */
    public function getDescription()
    {
        return $this->description;
    }
}