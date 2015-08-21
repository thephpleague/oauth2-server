<?php

namespace League\OAuth2\Server\ServerInterface;

interface AuthorizationServer extends GrantServer, ScopeServer, AccessTokenServer, AuthCodeServer
{

}
