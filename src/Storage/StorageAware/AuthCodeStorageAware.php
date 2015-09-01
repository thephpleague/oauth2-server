<?php
namespace League\OAuth2\Server\Storage\StorageAware;

use League\OAuth2\Server\Storage\AuthCodeInterface;


interface AuthCodeStorageAware
{
    /**
     * Set the auth code storage
     *
     * @param \League\OAuth2\Server\Storage\AuthCodeInterface $storage
     *
     * @return self
     */
    public function setAuthCodeStorage(AuthCodeInterface $storage);
    /**
     * Return the auth code storage
     *
     * @return \League\OAuth2\Server\Storage\AuthCodeInterface
     */
    public function getAuthCodeStorage();
}
