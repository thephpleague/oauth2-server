<?php

namespace RelationalExample\Storage;

use League\OAuth2\Server\Storage\ScopeInterface;
use League\OAuth2\Server\Storage\Adapter;
use League\OAuth2\Server\Entity\ScopeEntity;

use Illuminate\Database\Capsule\Manager as Capsule;

class ScopeStorage extends Adapter implements ScopeInterface
{
    /**
     * {@inheritdoc}
     */
    public function get($scope, $grantType = null)
    {
        $result = Capsule::table('oauth_scopes')
                                ->where('id', $scope)
                                ->get();

        if (count($result) === 0) {
            return null;
        }

        return (new ScopeEntity($this->server))
                            ->setId($result[0]['id'])
                            ->setDescription($result[0]['description']);
    }
}
