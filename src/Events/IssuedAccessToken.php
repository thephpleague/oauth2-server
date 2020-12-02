<?php

namespace League\OAuth2\Server\Events;

class IssuedAccessToken extends AbstractRequestEvent
{
    public const ACCESS_TOKEN_ISSUED = 'access_token.issued';
}
