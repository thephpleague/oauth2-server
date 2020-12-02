<?php

namespace League\OAuth2\Server\Events;

class IssuedRefreshToken extends AbstractRequestEvent
{
    public const REFRESH_TOKEN_ISSUED = 'refresh_token.issued';
}
