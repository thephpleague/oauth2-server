<?php

namespace MongoDBExample\Storage;

use League\OAuth2\Server\Storage\AccessTokenInterface;
use MongoDBExample\Document\OAuthAccessToken;
use League\OAuth2\Server\Entity\AccessTokenInterface as AccessTokenEntityInterface;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;

class AccessTokenStorage extends BaseStorage implements AccessTokenInterface
{
    /**
     * Get an instance of Entity\AccessTokenEntity
     */
    public function get($token){

        if($AccessToken = $this->documentManager->getRepository("MongoDBExample\Document\OAuthAccessToken")->find($token))
            return $AccessToken;
        else 
            return;
    }

    /**
     * Get the scopes for an access token
     */
    public function getScopes(AccessTokenEntityInterface $token){

        if($AccessToken = $this->documentManager->getRepository("MongoDBExample\Document\OAuthAccessToken")->find($token->getId()))
            return $AccessToken->getScopes();
        
        return array();
    }

    /**
     * Creates a new access token
     */
    public function create($token, $expireTime, $sessionId){
        $accessToken = new OAuthAccessToken();
        $accessToken->setId($token);
        $accessToken->setExpireTime($expireTime);
        $accessToken->setSession($this->documentManager->getRepository("MongoDBExample\Document\OAuthSession")->find($sessionId));
        $this->documentManager->persist($accessToken);
        $this->documentManager->flush();
    }

    /**
     * Associate a scope with an acess token
     */
    public function associateScope(AccessTokenEntityInterface $token, ScopeEntityInterface $scope){
        $token->getScopes()->add($scope);
    }

    /**
     * Delete an access token
     */
    public function delete(AccessTokenEntityInterface $token){
        $this->documentManager->remove($token);
        $this->documentManager->flush();
    }
}