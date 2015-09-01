<?php
namespace League\OAuth2\Server\ServerInterface;

interface AuthorizationServer extends
    GrantServer,
    ScopeServer,
    AccessTokenServer,
    AuthCodeServer,
    Server
{
    /**
     * Returns response types
     *
     * @return array
     */
    public function getResponseTypes();
}
