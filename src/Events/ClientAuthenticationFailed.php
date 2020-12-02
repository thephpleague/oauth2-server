<?php

namespace League\OAuth2\Server\Events;

class ClientAuthenticationFailed extends AbstractRequestEvent
{
    public const CLIENT_AUTHENTICATION_FAILED = 'client.authentication.failed';
}
