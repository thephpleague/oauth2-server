<?php
namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\Interfaces\UserEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use OAuth2ServerExamples\Entities\UserEntity;

class UserRepository implements UserRepositoryInterface
{
    /**
     * Get a user
     *
     * @param string $username
     * @param string $password
     *
     * @return UserEntityInterface
     */
    public function getByCredentials($username, $password)
    {
        return new UserEntity();
    }
}
