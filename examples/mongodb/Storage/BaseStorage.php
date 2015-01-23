<?php

namespace MongoDBExample\Storage;

use League\OAuth2\Server\Storage\StorageInterface;
use League\OAuth2\Server\AbstractServer;

/**
 * Base storage class for all Sotrage implementations
 */
class BaseStorage implements StorageInterface
{
    /**
     * @var \Doctrine\ODM\MongoDB\DocumentManager
     */
    protected $documentManager;

    /**
     * Constructor
     * @param \Doctrine\ODM\MongoDB\DocumentManager $documentManager
     */
    public function __construct($documentManager){
        $this->documentManager = $documentManager;
    }

    /**
     * @var \League\OAuth2\Server\AbstractServer
     */
    protected $server;

    /**
     * {@inheritDoc}
     */
    public function setServer(AbstractServer $server){
        $this->server = $server;
    }
}