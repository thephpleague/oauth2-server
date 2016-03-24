<?php

namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use OAuth2ServerExamples\Entities\ScopeEntity;
use OAuth2ServerExamples\Entities\UserEntity;

class UserRepository implements UserRepositoryInterface
{
    /**
     * @inheritdoc
     */
    public function getUserEntityByUserCredentials(
        $username,
        $password,
        $grantType,
        ClientEntityInterface $clientEntity
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
