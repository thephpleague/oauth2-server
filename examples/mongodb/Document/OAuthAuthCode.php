<?php

namespace MongoDBExample\Document;

use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;
use Doctrine\Common\Collections\ArrayCollection;
use League\OAuth2\Server\Entity\AuthCodeInterface as AuthCodeEntityInterface;
use League\OAuth2\Server\Entity\SessionInterface as SessionEntityInterface;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;

/** 
 * @ODM\Document
 */
class OAuthAuthCode implements AuthCodeEntityInterface {

    /**
     * @ODM\Id(strategy="NONE")
     */
    public $id;

    /**
     * @ODM\Field(name="expire_time",type="int")
     */
    protected $ExpireTime;

    /**
     * @ODM\ReferenceOne(targetDocument="MongoDBExample\Document\OAuthSession",simple=true)
     */
    protected $Session;

    /**
     * @ODM\ReferenceMany(targetDocument="MongoDBExample\Document\OAuthScope",simple=true)
     */
    protected $Scopes;

    /**
     * @ODM\Field(name="redirect_uri")
     */
    protected $RedirectURI;

    /**
     * Constructor
     */
    public function __construct(){
        $this->Scopes = new ArrayCollection();
    }

    /**
     * {@inheritDoc}
     */
    public function setRedirectUri($redirectUri){
        $this->RedirectURI = $redirectUri;
        
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getRedirectUri(){
        return $this->RedirectURI;
    }

    /**
     * {@inheritDoc}
     */
    public function generateRedirectUri($state = null, $queryDelimeter = '?'){
        $uri = $this->getRedirectUri();
        $uri .= (strstr($this->getRedirectUri(), $queryDelimeter) === false) ? $queryDelimeter : '&';

        return $uri.http_build_query([
                'code'  =>  $this->getId(),
                'state' =>  $state,
        ]);
    }

    /**
     * {@inheritDoc}
     */
    public function getSession(){
        if(isset($this->Session->__isInitialized__) && !$this->Session->__isInitialized__) {
            $this->Session->__load();
        }
        return $this->Session;
    }

    /**
     * {@inheritDoc}
     */
    public function getScopes(){
        return $this->Scopes;
    }

    /**
     * {@inheritDoc}
     */
    public function setSession(SessionEntityInterface $session)
    {
        $this->Session = $session;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function setExpireTime($expireTime)
    {
        $this->ExpireTime = $expireTime;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getExpireTime()
    {
        return $this->ExpireTime;
    }

    /**
     * {@inheritDoc}
     */
    public function isExpired()
    {
        return ((time() - $this->ExpireTime) > 0);
    }

    /**
     * {@inheritDoc}
     */
    public function setId($id = NULL)
    {
        $this->id = $id;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * {@inheritDoc}
     */
    public function associateScope(ScopeEntityInterface $scope)
    {
        if (!$this->Scopes->contains($scope)) {
            $this->Scopes->add($scope);
        }

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function __toString(){
        if ($this->id === null) {
            return '';
        }

        return $this->id;
    }

    /**
     * {@inheritDoc}
     */
    public function expire(){
        $dm = \MongoDBExample\Config\DM::get();
        $dm->remove($this);
        $dm->flush();
    }

    /**
     * {@inheritDoc}
     */
    public function save(){
        $dm = \MongoDBExample\Config\DM::get();
        $dm->persist($this);
        $dm->flush();
    }
}