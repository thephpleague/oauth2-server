<?php
namespace League\OAuth2\Server\Storage\StorageAware;

use League\OAuth2\Server\Storage\SessionInterface;

interface SessionStorageAware
{
    /**
     * Set the session storage
     *
     * @param \League\OAuth2\Server\Storage\SessionInterface $storage
     *
     * @return self
     */
    public function setSessionStorage(SessionInterface $storage);

    /**
     * Return the session storage
     *
     * @return \League\OAuth2\Server\Storage\SessionInterface
     */
    public function getSessionStorage();
}