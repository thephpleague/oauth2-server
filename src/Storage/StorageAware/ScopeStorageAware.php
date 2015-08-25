<?php
namespace League\OAuth2\Server\Storage\StorageAware;

use League\OAuth2\Server\Storage\ScopeInterface;

interface ScopeStorageAware
{
    /**
     * Set the scope storage
     *
     * @param \League\OAuth2\Server\Storage\ScopeInterface $storage
     *
     * @return self
     */
    public function setScopeStorage(ScopeInterface $storage);

    /**
     * Return the scope storage
     *
     * @return \League\OAuth2\Server\Storage\ScopeInterface
     */
    public function getScopeStorage();
}