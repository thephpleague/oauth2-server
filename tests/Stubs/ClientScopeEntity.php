<?php

namespace LeagueTests\Stubs;

use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeInterface;
use League\OAuth2\Server\Entities\Traits\ClientTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\ScopeEntityTrait;

class ClientScopeEntity implements ClientEntityInterface, ScopeInterface
{
    use EntityTrait, ClientTrait, ScopeEntityTrait;

    public function setRedirectUri($uri)
    {
        $this->redirectUri = $uri;
    }

    public function setName($name)
    {
        $this->name = $name;
    }
}
