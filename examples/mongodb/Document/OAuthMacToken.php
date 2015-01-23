<?php

namespace MongoDBExample\Document;

use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;
use League\OAuth2\Server\Entity\AccessTokenInterface as AccessTokenEntityInterface;

/** 
 * @ODM\Document
 */
class OAuthMacToken{

    /**
     * @ODM\Id(strategy="NONE")
     */
    public $id;    

    /**
     * @ODM\ReferenceOne(targetDocument="MongoDBExample\Document\OAuthAccessToken",simple=true)
     */
    protected $AccessToken;

    /**
     * {@inheritDoc}
     */
    public function setAccessToken(AccessTokenEntityInterface $accessTokenEntity)
    {
        $this->AccessToken = $accessTokenEntity;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getAccessToken()
    {
        if(isset($this->AccessToken->__isInitialized__) && !$this->AccessToken->__isInitialized__) {
            $this->AccessToken->__load();
        }

        return $this->AccessToken;
    }

    /**
     * {@inheritDoc}
     */
    public function setId($id)
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
}