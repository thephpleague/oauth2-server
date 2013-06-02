<?php

namespace League\OAuth2\Server\Storage\Fluent;

use \Illuminate\Support\Facades\DB as DB;
use \League\OAuth2\Server\Storage\ScopeInterface;

class Scope implements ScopeInterface {

    public function getScope($scope, $clientId = null, $grantType = null)
    {
         $result = DB::table('oauth_scopes')
                    ->where('key', $scope)
                    ->first();

        if (is_null($result)) {
            return false;
        }

        return array(
            'id'          => $result->id,
            'scope'       => $result->key,
            'name'        => $result->name,
            'description' => $result->description
        );
    }
}