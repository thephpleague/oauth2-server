<?php

namespace LeagueTests\ResponseTypes;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;

class BearerTokenResponseWithParams extends BearerTokenResponse
{
    protected function getExtraParams(AccessTokenEntityInterface $accessToken)
    {
        return ['foo' => 'bar', 'token_type' => 'Should not overwrite'];
    }
}
