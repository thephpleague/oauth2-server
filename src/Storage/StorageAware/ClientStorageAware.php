<?php
namespace League\OAuth2\Server\Storage\StorageAware;

use League\OAuth2\Server\Storage\ClientInterface;

interface ClientStorageAware
{
    /**
     * Set the client storage
     *
     * @param \League\OAuth2\Server\Storage\ClientInterface $storage
     *
     * @return self
     */
    public function setClientStorage(ClientInterface $storage);

    /**
     * Return the client storage
     *
     * @return \League\OAuth2\Server\Storage\ClientInterface
     */
    public function getClientStorage();
}