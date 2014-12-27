<?php
/**
 * OAuth 2.0 scope entity
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
 * Scope entity class
 */
class ScopeEntity implements ScopeInterface
{
    /**
     * Scope identifier
     *
     * @var string
     */
    protected $id;

    /**
     * Scope description
     *
     * @var string
     */
    protected $description;

    /**
     * Authorization or resource server
     *
     * @var \League\OAuth2\Server\AbstractServer
     */
    protected $server;

    /**
     * __construct
     *
     * @param \League\OAuth2\Server\AbstractServer $server
     *
     * @return self
     */
    public function __construct(AbstractServer $server)
    {
        $this->server = $server;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * {@inheritDoc}
     */
    public function setId($id)
    {
        $this->id = $id;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getDescription()
    {
        return $this->description;
    }

    /**
     * {@inheritDoc}
     */
    public function setDescription($description)
    {
        $this->description = $description;

        return $this;
    }

    /**
     * Returns a JSON object when entity is passed into json_encode
     *
     * @return array
     */
    public function jsonSerialize()
    {
        return [
            'id'    =>  $this->getId(),
            'description'   =>  $this->getDescription()
        ];
    }
}
