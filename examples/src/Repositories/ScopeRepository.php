<?php
namespace OAuth2ServerExamples\Repositories;

use League\OAuth2\Server\Entities\ScopeEntity;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

class ScopeRepository implements ScopeRepositoryInterface
{
    /**
     * Return information about a scope
     *
     * @param string $scopeIdentifier The scope identifier
     * @param string $grantType       The grant type used in the request (default = "null")
     * @param string $clientId        The client sending the request (default = "null")
     *
     * @return \League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface
     */
    public function get($scopeIdentifier, $grantType = null, $clientId = null)
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
