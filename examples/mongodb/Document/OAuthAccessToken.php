<?php

namespace MongoDBExample\Document;

use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;
use League\OAuth2\Server\Entity\AccessTokenInterface as AccessTokenEntityInterface;
use League\OAuth2\Server\Entity\SessionInterface as SessionEntityInterface;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;
use Doctrine\Common\Collections\ArrayCollection;

/** 
 * @ODM\Document
 */
class OAuthAccessToken implements AccessTokenEntityInterface {

    /**
     * @ODM\Id(strategy="NONE")
     **/
    public $id;

    /**
     * @ODM\ReferenceOne(targetDocument="MongoDBExample\Document\OAuthSession",simple=true)
     */
    protected $Session;

    /**
     * @ODM\Field(name="expire_time",type="int")
     */
    protected $ExpireTime;

    /**
     * @ODM\ReferenceMany(targetDocument="MongoDBExample\Document\OAuthScope",simple=true)
     */
    public $Scopes;

    public function __construct(){
        $this->Scopes = new ArrayCollection();
    }

    public function getSession()
    {
        if(isset($this->Session->__isInitialized__) && !$this->Session->__isInitialized__) {
            $this->Session->__load();
        }
        return $this->Session;
    }

    public function hasScope($scope){
        return $this->Scopes->contains($scope);
    }

    public function getScopes(){
        return $this->Scopes;
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