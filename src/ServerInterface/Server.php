<?php
namespace League\OAuth2\Server\ServerInterface;

use League\OAuth2\Server\Storage\StorageAware\StorageAware;

interface Server extends EventDispatcher, RequestAware, TokenTypeAware, StorageAware
{

}