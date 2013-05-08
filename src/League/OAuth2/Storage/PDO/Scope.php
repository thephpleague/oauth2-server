<?php

namespace League\OAuth2\Storage\PDO;

use League\OAuth2\Storage\ScopeInterface;

class Scope implements ScopeInterface
{
    public function getScope($scope, $clientId = null, $grantType = null)
    {
        $db = \ezcDbInstance::get();

        $stmt = $db->prepare('SELECT * FROM oauth_scopes WHERE oauth_scopes.key = :scope');
        $stmt->bindValue(':scope', $scope);
        $stmt->execute();

        $row = $stmt->fetchObject();

        if ($row === false) {
            return false;
        }

        return array(
            'id' =>  $row->id,
            'scope' =>  $row->key,
            'name'  =>  $row->name,
            'description'  =>  $row->description
        );

    }
}