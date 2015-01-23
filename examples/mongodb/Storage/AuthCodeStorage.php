<?php

namespace MongoDBExample\Storage;

use League\OAuth2\Server\Storage\AuthCodeInterface;
use MongoDBExample\Document\OAuthAuthCode;
use League\OAuth2\Server\Entity\AuthCodeInterface as AuthCodeEntityInterface;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;

class AuthCodeStorage extends BaseStorage implements AuthCodeInterface
{
    /**
     * Get the auth code
     *
     * @param string $code
     *
     * @return \League\OAuth2\Server\Entity\AuthCodeEntity
     */
    public function get($code){
        if($AccessToken = $this->documentManager->getRepository("MongoDBExample\Document\OAuthAuthCode")->find($code))
            return $AccessToken;
        else 
            return;
    }

    /**
     * Create an auth code.
     *
     * @param string  $token       The token ID
     * @param integer $expireTime  Token expire time
     * @param integer $sessionId   Session identifier
     * @param string  $redirectUri Client redirect uri
     *
     * @return void
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
     * Get the scopes for an access token
     *
     * @param \League\OAuth2\Server\Entity\AuthCodeEntity $token The auth code
     *
     * @return array Array of \League\OAuth2\Server\Entity\ScopeEntity
    */
    public function getScopes(AuthCodeEntityInterface $token){
        if($AuthCode = $this->documentManager->getRepository("MongoDBExample\Document\OAuthAuthCode")->find($token->getId()))
            return $AuthCode->getScopes();

        return array();
    }

    /**
     * Associate a scope with an acess token
     *
     * @param \League\OAuth2\Server\Entity\AuthCodeEntity $token The auth code
     * @param \League\OAuth2\Server\Entity\ScopeEntity    $scope The scope
     *
     * @return void
     */
    public function associateScope(AuthCodeEntityInterface $token, ScopeEntityInterface $scope){
        $token->getScopes()->add($scope);
    }

    /**
     * Delete an access token
     *
     * @param \League\OAuth2\Server\Entity\AuthCodeEntity $token The access token to delete
     *
     * @return void
     */
    public function delete(AuthCodeEntityInterface $token){
        $this->documentManager->remove($token);
        $this->documentManager->flush();
    }
}