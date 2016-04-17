<?php

namespace LeagueTests\Stubs;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;

class UserEntity implements UserEntityInterface
{
    use EntityTrait;

    public function __construct()
    {
        $this->setIdentifier(123);
    }
}
