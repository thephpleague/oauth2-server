<?php

namespace OAuth2ServerExamples\Entities;

use League\OAuth2\Server\Entities\Interfaces\UserEntityInterface;

class UserEntity implements UserEntityInterface
{
    /**
     * Return the user's identifier.
     *
     * @return mixed
     */
    public function getIdentifier()
    {
        return 1;
    }
}
