<?php

namespace OAuth2\Storage;

interface ScopeInterface
{
    /**
     * Return information about a scope
     *
     * Example SQL query:
     *
     * <code>
     * SELECT * FROM scopes WHERE scope = $scope
     * </code>
     *
     * Response:
     *
     * <code>
     * Array
     * (
     *     [id] => (int) The scope's ID
     *     [scope] => (string) The scope itself
     *     [name] => (string) The scope's name
     *     [description] => (string) The scope's description
     * )
     * </code>
     *
     * @param  string     $scope The scope
     * @return bool|array If the scope doesn't exist return false
     */
    public function get($scope);
}
