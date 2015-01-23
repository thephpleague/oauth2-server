<?php

namespace MongoDBExample\Storage;

use League\OAuth2\Server\Storage\SessionInterface;
use MongoDBExample\Document\OAuthSession;
use League\OAuth2\Server\Entity\AccessTokenInterface as AccessTokenEntityInterface;
use League\OAuth2\Server\Entity\AuthCodeInterface as AuthCodeEntityInterface;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;
use League\OAuth2\Server\Entity\SessionInterface as SessionEntityInterface;

/**
 * Storage class for sessions
 */
class SessionStorage extends BaseStorage implements SessionInterface
{
    /**
     * {@inheritDoc}
     */
    public function getByAccessToken(AccessTokenEntityInterface $accessToken){
        return $accessToken->getSession();
    }

    /**
     * {@inheritDoc}
     */
    public function getByAuthCode(AuthCodeEntityInterface $authCode){
        return $authCode->getSession();
    }

    /**
     * {@inheritDoc}
     */
    public function getScopes(SessionEntityInterface $session){

        if($Session = $this->documentManager->getRepository("MongoDBExample\Document\OAuthSession")->find($session->getId()))
            return $Session->getScopes();

        return array();
    }

    /**
     * {@inheritDoc}
     */
    public function create($ownerType, $ownerId, $clientId, $clientRedirectUri = null){
        $session = new OAuthSession();
        $session->setOwner($ownerType, $ownerId);
        $session->associateClient($this->documentManager->getRepository("MongoDBExample\Document\OAuthClient")->find($clientId));
        $this->documentManager->persist($session);
        $this->documentManager->flush();
        return $session->id;
    }

    /**
     * {@inheritDoc}
     */
    public function associateScope(SessionEntityInterface $session, ScopeEntityInterface $scope){
        $session->getScopes()->add($scope);
    }
}
