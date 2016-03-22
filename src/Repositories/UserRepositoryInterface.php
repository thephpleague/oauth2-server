<?php

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface;

interface UserRepositoryInterface extends RepositoryInterface
{
    /**
     * Get a user entity.
     *
     * @param string                                                          $username
     * @param string                                                          $password
     * @param string                                                          $grantType    The grant type used
     * @param \League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface $clientEntity
     * @param ScopeEntityInterface[]                                          $scopes
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\UserEntityInterface
     */
    public function getUserEntityByUserCredentials(
        $username,
        $password,
        $grantType,
        ClientEntityInterface $clientEntity,
        array &$scopes
    );
}
