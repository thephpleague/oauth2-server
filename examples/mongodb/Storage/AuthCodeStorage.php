<?php

namespace MongoDBExample\Storage;

use League\OAuth2\Server\Storage\AuthCodeInterface;
use MongoDBExample\Document\OAuthAuthCode;
use League\OAuth2\Server\Entity\AuthCodeInterface as AuthCodeEntityInterface;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;

/**
 * Storage class for auth codes
 */
class AuthCodeStorage extends BaseStorage implements AuthCodeInterface
{
    /**
     * {@inheritDoc}
     */
    public function get($code){
        if($AccessToken = $this->documentManager->getRepository("MongoDBExample\Document\OAuthAuthCode")->find($code))
            return $AccessToken;
        else 
            return;
    }

    /**
     * {@inheritDoc}
     */
    public function create($token, $expireTime, $sessionId, $redirectUri){
        $authCode = new OAuthAuthCode();
        $authCode->setId($token);
        $authCode->setRedirectUri($redirectUri);
        $authCode->setExpireTime($expireTime);
        $authCode->setSession($this->documentManager->getRepository("MongoDBExample\Document\OAuthSession")->find($sessionId));
        $this->documentManager->persist($authCode);
        $this->documentManager->flush();
    }

    /**
     * {@inheritDoc}
     */
    public function getScopes(AuthCodeEntityInterface $token){
        if($AuthCode = $this->documentManager->getRepository("MongoDBExample\Document\OAuthAuthCode")->find($token->getId()))
            return $AuthCode->getScopes();

        return array();
    }

    /**
     * {@inheritDoc}
     */
    public function associateScope(AuthCodeEntityInterface $token, ScopeEntityInterface $scope){
        $token->getScopes()->add($scope);
    }

    /**
     * {@inheritDoc}
     */
    public function delete(AuthCodeEntityInterface $token){
        $this->documentManager->remove($token);
        $this->documentManager->flush();
    }
}