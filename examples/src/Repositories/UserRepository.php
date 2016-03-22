<?php

namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use OAuth2ServerExamples\Entities\ScopeEntity;
use OAuth2ServerExamples\Entities\UserEntity;

class UserRepository implements UserRepositoryInterface
{
    /**
     * Get a user entity.
     *
     * @param string                                                          $username
     * @param string                                                          $password
     * @param string                                                          $grantType The grant type used
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
    ) {
        if ($username === 'alex' && $password === 'whisky') {
            $scope = new ScopeEntity();
            $scope->setIdentifier('email');
            $scopes[] = $scope;

            return new UserEntity();
        }

        return;
    }
}
