<?php

namespace MongoDBExample\Storage;

use League\OAuth2\Server\Storage\AccessTokenInterface;
use MongoDBExample\Document\OAuthAccessToken;
use League\OAuth2\Server\Entity\AccessTokenInterface as AccessTokenEntityInterface;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;

/**
 * Storage class for access tokens
 */
class AccessTokenStorage extends BaseStorage implements AccessTokenInterface
{
    /**
     * {@inheritDoc}
     */
    public function get($token){

        if($AccessToken = $this->documentManager->getRepository("MongoDBExample\Document\OAuthAccessToken")->find($token))
            return $AccessToken;
        else 
            return;
    }

    /**
     * {@inheritDoc}
     */
    public function getScopes(AccessTokenEntityInterface $token){

        if($AccessToken = $this->documentManager->getRepository("MongoDBExample\Document\OAuthAccessToken")->find($token->getId()))
            return $AccessToken->getScopes();
        
        return array();
    }

    /**
     * {@inheritDoc}
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
     * {@inheritDoc}
     */
    public function associateScope(AccessTokenEntityInterface $token, ScopeEntityInterface $scope){
        $token->getScopes()->add($scope);
    }

    /**
     * {@inheritDoc}
     */
    public function delete(AccessTokenEntityInterface $token){
        $this->documentManager->remove($token);
        $this->documentManager->flush();
    }
}