<?php


namespace League\OAuth2\Server\Storage\StorageAware;


interface StorageAware extends
    AccessTokenStorageAware,
    AuthCodeStorageAware,
    ClientStorageAware,
    MacTokenStorageAware,
    RefreshTokenStorageAware,
    ScopeStorageAware,
    SessionStorageAware
{

}