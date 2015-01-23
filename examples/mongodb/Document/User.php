<?php

namespace MongoDBExample\Document;

use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;
use Doctrine\Common\Collections\ArrayCollection;

/** 
 * @ODM\Document
 */
class User
{
    /**
     * @ODM\Id(strategy="NONE")
     **/
    public $id;

    /** 
     * @ODM\Field(name="password") 
     */
    public $Password;

    /** 
     * @ODM\Field(name="name") 
     */
    public $Name;

    /** 
     * @ODM\Field(name="email") 
     */
    public $Email;

    /** 
     * @ODM\Field(name="photo") 
     */
    public $Photo;
}