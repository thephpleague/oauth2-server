<?php

namespace MongoDBExample\Storage;

use League\OAuth2\Server\Storage\SessionInterface;
use MongoDBExample\Document\OAuthSession;
use League\OAuth2\Server\Entity\AccessTokenInterface as AccessTokenEntityInterface;
use League\OAuth2\Server\Entity\AuthCodeInterface as AuthCodeEntityInterface;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;
use League\OAuth2\Server\Entity\SessionInterface as SessionEntityInterface;

class SessionStorage extends BaseStorage implements SessionInterface
{
	/**
	 * Get a session from an access token
	 */
	public function getByAccessToken(AccessTokenEntityInterface $accessToken){
		return $accessToken->getSession();
	}
	
	/**
	 * Get a session from an auth code
	*/
	public function getByAuthCode(AuthCodeEntityInterface $authCode){
		return $authCode->getSession();
	}
	
	/**
	 * Get a session's scopes
	*/
	public function getScopes(SessionEntityInterface $session){
		
		if($Session = $this->documentManager->getRepository("MongoDBExample\Document\OAuthSession")->find($session->getId()))
			return $Session->getScopes();
		
		return array();
	}
	
	/**
	 * Create a new session
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
	 * Associate a scope with a session
	*/
	public function associateScope(SessionEntityInterface $session, ScopeEntityInterface $scope){
		$session->getScopes()->add($scope);
	}
}
