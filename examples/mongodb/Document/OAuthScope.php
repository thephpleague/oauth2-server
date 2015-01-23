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
     */
    public $id;

    /**
     * @ODM\Field(name="description")
     */
    protected $Description;

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
    public function setId($id){
        $this->id = $id;
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getDescription()
    {
        return $this->Description;
    }

    /**
     * {@inheritDoc}
     */
    public function setDescription($description){
        $this->Description = $description;
        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function jsonSerialize()
    {
        return [
            'id'    =>  $this->getId(),
            'description'   =>  $this->getDescription()
        ];
    }
}