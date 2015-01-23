<?php

namespace MongoDBExample\Storage;

use League\OAuth2\Server\Storage\ScopeInterface;
class ScopeStorage extends BaseStorage implements ScopeInterface
{
    /**
     * Return information about a scope
     */
    public function get($scope, $grantType = null, $clientId = null){
        if($Scope = $this->documentManager->getRepository("MongoDBExample\Document\OAuthScope")->find($scope))
            return $Scope;
        else 
            return;
    }
}