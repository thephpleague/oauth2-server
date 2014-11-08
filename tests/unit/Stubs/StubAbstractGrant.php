<?php

namespace LeagueTests\Stubs;

class StubAbstractGrant extends \League\OAuth2\Server\Grant\AbstractGrant
{
    protected $responseType = 'foobar';

    public function completeFlow()
    {
        return true;
    }

    public function getAuthorizationServer()
    {
        return $this->server;
    }
}
