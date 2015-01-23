<?php

namespace MongoDBExample\Storage;

use League\OAuth2\Server\Storage\ScopeInterface;

/**
 * Storage class for scopes
 */
class ScopeStorage extends BaseStorage implements ScopeInterface
{
    /**
     * {@inheritDoc}
     */
    public function get($scope, $grantType = null, $clientId = null){
        if($Scope = $this->documentManager->getRepository("MongoDBExample\Document\OAuthScope")->find($scope))
            return $Scope;
        else 
            return;
    }
}