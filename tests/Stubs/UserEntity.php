<?php

namespace LeagueTests\Stubs;

use League\OAuth2\Server\Entities\UserEntityInterface;

class UserEntity implements UserEntityInterface
{
    public function getIdentifier()
    {
        return 123;
    }
}
