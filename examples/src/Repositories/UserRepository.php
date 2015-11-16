<?php
namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use OAuth2ServerExamples\Entities\UserEntity;

class UserRepository implements UserRepositoryInterface
{
    /**
     * Get a user entity
     *
     * @param string $username
     * @param string $password
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\UserEntityInterface
     */
    public function getUserEntityByUserCredentials($username, $password)
    {
        if ($username === 'alex' && $password === 'whisky') {
            return new UserEntity();
        }

        return null;
    }
}
