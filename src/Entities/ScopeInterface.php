<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entities;

interface ScopeInterface
{
    /**
     * Associate a scope with the entity.
     *
     * @param ScopeEntityInterface $scope
     */
    public function addScope(ScopeEntityInterface $scope);

    /**
     * Return an array of scopes associated with the entity.
     *
     * @return ScopeEntityInterface[]
     */
    public function getScopes();
}
