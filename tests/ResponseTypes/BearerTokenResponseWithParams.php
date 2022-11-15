<?php

namespace LeagueTests\ResponseTypes;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;

class BearerTokenResponseWithParams extends BearerTokenResponse
{

    /**
     * @return array<string, string>
     */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        return ['foo' => 'bar', 'token_type' => 'Should not overwrite'];
    }
}
