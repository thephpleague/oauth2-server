<?php

namespace MongoDBExample\Document;

use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;
use League\OAuth2\Server\Entity\RefreshTokenInterface as RefreshTokenEntityInterface;
use League\OAuth2\Server\Entity\AccessTokenInterface as AccessTokenEntityInterface;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;
use League\OAuth2\Server\Entity\SessionInterface as SessionEntityInterface;

/** 
 * @ODM\Document
 */
class OAuthRefreshToken implements RefreshTokenEntityInterface {
	
	/**
	 * @ODM\Id(strategy="NONE")
	 */
	public $id;    
    
	/**
	 * @ODM\Field(name="expire_time",type="int")
	 */
	protected $ExpireTime;
	
	/**
	 * @ODM\ReferenceOne(targetDocument="MongoDBExample\Document\OAuthAccessToken",simple=true)
	 */
	protected $AccessToken;
	
	/**
	 * @ODM\ReferenceOne(targetDocument="MongoDBExample\Document\OAuthSession",simple=true)
	 */
	protected $Session;
	
	/**
	 * @ODM\ReferenceMany(targetDocument="MongoDBExample\Document\OAuthScope",simple=true)
	 */
	public $Scopes;
	
	public function setAccessTokenId($accessTokenId){
		return $this;
	}
	
	public function setAccessToken(AccessTokenEntityInterface $accessTokenEntity)
	{
		$this->AccessToken = $accessTokenEntity;
	
		return $this;
	}
	
	public function getAccessToken()
	{
		if(isset($this->AccessToken->__isInitialized__) && !$this->AccessToken->__isInitialized__) {
			$this->AccessToken->__load();
		}
	
		return $this->AccessToken;
	}
	
	public function setSession(SessionEntityInterface $session)
	{
		$this->Session = $session;
	
		return $this;
	}
	
	public function setExpireTime($expireTime)
	{
		$this->ExpireTime = $expireTime;
	
		return $this;
	}
	
	public function getExpireTime()
	{
		return $this->ExpireTime;
	}
	
	public function isExpired()
	{
		return ((time() - $this->ExpireTime) > 0);
	}
		
	public function setId($id = NULL)
	{
		$this->id = $id;
	
		return $this;
	}
	
	public function getId()
	{
		return $this->id;
	}
	
	public function associateScope(ScopeEntityInterface $scope)
	{
		if (!$this->Scopes->contains($scope)) {
			$this->Scopes->add($scope);
		}
	
		return $this;
	}
	
	public function __toString(){
		if ($this->id === null) {
            return '';
        }

        return $this->id;
	}

    public function expire(){
		$dm = \MongoDBExample\Config\DM::get();
		$dm->remove($this);
		$dm->flush();
	}

    public function save(){
		$dm = \MongoDBExample\Config\DM::get();
		$dm->persist($this);
		$dm->flush();
	}
}