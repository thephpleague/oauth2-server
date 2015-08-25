<?php
namespace League\OAuth2\Server\Storage\StorageAware;

use League\OAuth2\Server\Storage\AccessTokenInterface;

interface AccessTokenStorageAware
{
    /**
     * Set the access token storage
     *
     * @param \League\OAuth2\Server\Storage\AccessTokenInterface $storage
     *
     * @return self
     */
    public function setAccessTokenStorage(AccessTokenInterface $storage);

    /**
     * Return the access token storage
     *
     * @return \League\OAuth2\Server\Storage\AccessTokenInterface
     */
    public function getAccessTokenStorage();
}
