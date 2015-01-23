<?php

namespace MongoDBExample\Document;

use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;
use League\OAuth2\Server\Entity\ClientInterface as ClientEntityInterface;

/** 
 * @ODM\Document
 */
class OAuthClient implements ClientEntityInterface {

    /**
     * @ODM\Id(strategy="NONE")
     */
    public $id;

    /**
     * @ODM\Field(name="secret")
     */
    protected $Secret;

    /**
     * @ODM\Field(name="name")
     */
    protected $Name;

    /**
     * @ODM\Field(name="redirect_uri")
     */
    protected $RedirectURI;

    /**
     * {@inheritDoc}
     */
    public function getId() {
        return $this->id;
    }

    /**
     * {@inheritDoc}
     */
    public function setId($id){
        $this->id = $id;
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getSecret() {
        return $this->Secret;
    }

    /**
     * {@inheritDoc}
     */
    public function setSecret($secret){
        $this->Secret = $secret;
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getName() {
        return $this->Name;
    }

    /**
     * {@inheritDoc}
     */
    public function setName($name){
        $this->Name = $name;
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getRedirectUri() {
        return $this->RedirectURI;
    }

    /**
     * {@inheritDoc}
     */
    public function setRedirectUri($redirectUri){
        $this->RedirectURI = $redirectUri;
        return $this;
    }
}