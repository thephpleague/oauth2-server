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
     **/
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

    public function getId() {
        return $this->id;
    }

    public function setId($id){
        $this->id = $id;
        return $this;
    }

    public function getSecret() {
        return $this->Secret;
    }

    public function setSecret($secret){
        $this->Secret = $secret;
        return $this;
    }

    public function getName() {
        return $this->Name;
    }

    public function setName($name){
        $this->Name = $name;
        return $this;
    }

    public function getRedirectUri() {
        return $this->RedirectURI;
    }

    public function setRedirectUri($redirectUri){
        $this->RedirectURI = $redirectUri;
        return $this;
    }
}