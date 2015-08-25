<?php
namespace League\OAuth2\Server\ServerInterface;

use League\OAuth2\Server\Storage\StorageAware\StorageAware;

interface AuthorizationServer extends
    GrantServer,
    ScopeServer,
    AccessTokenServer,
    AuthCodeServer,
    EventDispatcher,
    RequestAware,
    TokenTypeAware,
    StorageAware
{

}
