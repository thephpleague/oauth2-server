<?php
namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\ScopeEntity;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

class ScopeRepository implements ScopeRepositoryInterface
{
    /**
     * @inheritdoc
     */
    public function getScopeEntityByIdentifier($scopeIdentifier, $grantType, $clientId = null)
    {
        $scopes = [
            'basic' => [
                'description' => 'Basic details about you'
            ],
            'email' => [
                'description' => 'Your email address'
            ]
        ];

        if (array_key_exists($scopeIdentifier, $scopes) === false) {
            return null;
        }

        $scope = new ScopeEntity();
        $scope->setIdentifier($scopeIdentifier);

        return $scope;
    }
}
