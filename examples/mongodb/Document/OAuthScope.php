<?php

namespace MongoDBExample\Document;

use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;
use League\OAuth2\Server\Entity\ScopeInterface as ScopeEntityInterface;

/** 
 * @ODM\Document
 */
class OAuthScope implements ScopeEntityInterface {

    /**
     * @ODM\Id(strategy="NONE")
     **/
    public $id;

    /**
     * @ODM\Field(name="description")
     */
    protected $Description;

    public function getId()
    {
        return $this->id;
    }

    public function setId($id){
        $this->id = $id;
        return $this;
    }

    public function getDescription()
    {
        return $this->Description;
    }

    public function setDescription($description){
        $this->Description = $description;
        return $this;
    }

    /**
     * Returns a JSON object when entity is passed into json_encode
     *
     * @return array
     */
    public function jsonSerialize()
    {
        return [
            'id'    =>  $this->getId(),
            'description'   =>  $this->getDescription()
        ];
    }
}