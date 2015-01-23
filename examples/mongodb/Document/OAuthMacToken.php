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

    public function setId($id)
    {
        $this->id = $id;

        return $this;
    }

    public function getId()
    {
        return $this->id;
    }
}