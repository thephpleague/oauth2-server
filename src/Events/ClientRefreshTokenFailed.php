<?php

namespace League\OAuth2\Server\Events;

class ClientRefreshTokenFailed extends AbstractRequestEvent
{
    public const REFRESH_TOKEN_CLIENT_FAILED = 'refresh_token.client.failed';
}
