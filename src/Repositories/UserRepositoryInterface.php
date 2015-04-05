<?php
namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\Interfaces\UserEntityInterface;

interface UserRepositoryInterface extends RepositoryInterface
{
    /**
     * Get a user
     * @param string $username
     * @param string $password
     * @return UserEntityInterface
     */
    public function getByCredentials($username, $password);
}
