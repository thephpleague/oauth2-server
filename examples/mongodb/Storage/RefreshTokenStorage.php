<?php

namespace MongoDBExample\Storage;

use League\OAuth2\Server\Storage\RefreshTokenInterface;
use MongoDBExample\Document\OAuthRefreshToken;
use League\OAuth2\Server\Entity\RefreshTokenInterface as RefreshTokenEntityInterface;

class RefreshTokenStorage extends BaseStorage implements RefreshTokenInterface
{
	public function get($token){
		if($RefreshToken = $this->documentManager->getRepository("MongoDBExample\Document\OAuthRefreshToken")->find($token))
			return $RefreshToken;
		else 
			return;
	}
	
	public function create($token, $expireTime, $accessToken){
		$refreshToken = new OAuthRefreshToken();
		$refreshToken->setId($token);
		$refreshToken->setExpireTime($expireTime);
		$refreshToken->setAccessToken($this->documentManager->getRepository("MongoDBExample\Document\OAuthAccessToken")->find($accessToken));
		$this->documentManager->persist($refreshToken);
		$this->documentManager->flush();
	}
	
	public function delete(RefreshTokenEntityInterface $token){
		$this->documentManager->remove($token);
		$this->documentManager->flush();
	}
}