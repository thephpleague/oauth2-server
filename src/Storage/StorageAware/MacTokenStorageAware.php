<?php
namespace League\OAuth2\Server\Storage\StorageAware;

use League\OAuth2\Server\Storage\MacTokenInterface;

interface MacTokenStorageAware
{
    /**
     * @return MacTokenInterface
     */
    public function getMacStorage();

    /**
     * @param MacTokenInterface $macStorage
     */
    public function setMacStorage(MacTokenInterface $macStorage);
}