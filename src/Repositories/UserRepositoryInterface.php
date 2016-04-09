<?php

namespace League\OAuth2\Server\Repositories;

use League\OAuth2\Server\Entities\ClientEntityInterface;

interface UserRepositoryInterface extends RepositoryInterface
{
    /**
     * Get a user entity.
     *
     * @param string                                               $username
     * @param string                                               $password
     * @param string                                               $grantType    The grant type used
     * @param \League\OAuth2\Server\Entities\ClientEntityInterface $clientEntity
     *
     * @return \League\OAuth2\Server\Entities\UserEntityInterface
     */
    public function getUserEntityByUserCredentials(
        $username,
        $password,
        $grantType,
        ClientEntityInterface $clientEntity
    );
}
