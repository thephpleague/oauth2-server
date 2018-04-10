<?php

namespace League\OAuth2\Server\Entities\Traits;

use League\OAuth2\Server\Entities\ScopeEntityInterface;

trait ScopeEntityTrait
{
    /**
     * @var ScopeEntityInterface[]
     */
    protected $scopes = [];

    /**
     * Associate a scope with the token.
     *
     * @param ScopeEntityInterface $scope
     */
    public function addScope(ScopeEntityInterface $scope)
    {
        $this->scopes[$scope->getIdentifier()] = $scope;
    }

    /**
     * Return an array of scopes associated with the token.
     *
     * @return ScopeEntityInterface[]
     */
    public function getScopes()
    {
        return array_values($this->scopes);
    }
}
