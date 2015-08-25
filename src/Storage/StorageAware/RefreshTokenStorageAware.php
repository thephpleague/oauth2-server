<?php


namespace League\OAuth2\Server\Storage\StorageAware;


use League\OAuth2\Server\Storage\RefreshTokenInterface;

interface RefreshTokenStorageAware
{
    /**
     * Set the refresh token storage
     *
     * @param \League\OAuth2\Server\Storage\RefreshTokenInterface $storage
     *
     * @return self
     */
    public function setRefreshTokenStorage(RefreshTokenInterface $storage);

    /**
     * Return the refresh token storage
     *
     * @return \League\OAuth2\Server\Storage\RefreshTokenInterface
     */
    public function getRefreshTokenStorage();
}