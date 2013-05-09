<?php

namespace League\OAuth2\Server\Storage\PDO;

use League\OAuth2\Server\Storage\ScopeInterface;

class Scope implements ScopeInterface
{
    public function getScope($scope, $clientId = null, $grantType = null)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT * FROM oauth_scopes WHERE oauth_scopes.scope = :scope');
        $stmt->bindValue(':scope', $scope);
        $stmt->execute();

        $row = $stmt->fetchObject();

        if ($row === false) {
            return false;
        }

        return array(
            'id' =>  $row->id,
            'scope' =>  $row->scope,
            'name'  =>  $row->name,
            'description'  =>  $row->description
        );

    }
}