<?php

namespace MongoDBExample\Document;

use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;
use League\OAuth2\Server\Entity\SessionInterface as SessionEntityInterface;
use League\OAuth2\Server\Entity\ClientInterface as ClientEntityInterface;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;
use League\OAuth2\Server\Entity\AccessTokenInterface as AccessTokenEntityInterface;
use League\OAuth2\Server\Entity\RefreshTokenInterface as RefreshTokenEntityInterface;
use Doctrine\Common\Collections\ArrayCollection;

/** 
 * @ODM\Document
 */
class OAuthSession implements SessionEntityInterface {
	
	/**
	 * @ODM\Id(strategy="AUTO")
	 **/
	public $id;
	
	/**
	 * @ODM\ReferenceOne(targetDocument="MongoDBExample\Document\OAuthClient",simple=true)
	 */
	private $Client;
	
	/**
	 * @ODM\Field(name="owner_id")
	 */
	protected $OwnerId;
	
	/**
	 * @ODM\Field(name="owner_type")
	 */
	protected $OwnerType;
	
	/**
	 * @ODM\ReferenceMany(targetDocument="MongoDBExample\Document\OAuthScope",simple=true)
	 */
	protected $Scopes;
	
	/**
	 * @ODM\ReferenceOne(targetDocument="MongoDBExample\Document\OAuthAccessToken",simple=true)
	 */
	protected $AccessToken;
	
	/**
	 * @ODM\ReferenceOne(targetDocument="MongoDBExample\Document\OAuthRefreshToken",simple=true)
	 */
	protected $RefreshToken;
	
	public function __construct(){
		$this->Scopes = new ArrayCollection();
	}
	
	public function setId($id) {
		$this->id = $id;
		return $this;
	}
	
	public function getId(){
		return $this->id;
	}
	
	public function associateScope(ScopeEntityInterface $scope){
		if (!$this->Scopes->contains($scope)) {
			$this->Scopes->add($scope);
		}
		
		return $this;
	}
	
	public function hasScope($scope){
		return $this->Scopes->contains($scope);
	}
	
	public function getScopes(){
		return $this->Scopes;
	}
	
	public function associateAccessToken(AccessTokenEntityInterface $accessToken){
		$this->AccessToken = $accessToken;
		
		return $this;
	}
	
	public function associateRefreshToken(RefreshTokenEntityInterface $refreshToken){
		$this->RefreshToken = $refreshToken;
		
		return $this;
	}
	
	public function associateClient(ClientEntityInterface $client)
	{
		$this->Client = $client;
	
		return $this;
	}
	
	public function getClient()
	{
		return $this->Client;
	}
	
	public function setOwner($type, $id)
	{
		$this->OwnerType = $type;
		$this->OwnerId = $id;
	}
	
	public function getOwnerId()
	{
		return $this->OwnerId;
	}

	public function getOwnerType()
	{
		return $this->OwnerType;
	}
	
	public function save(){
		$dm = \MongoDBExample\Config\DM::get();
		$dm->persist($this);
		$dm->flush();
	}
}