<?php
namespace League\OAuth2\Server\Entities\Traits;

trait ClientEntityTrait
{
    /**
     * @var string
     */
    protected $name;

    /**
     * Get the client's name
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Set the client's name
     * @param string $name
     */
    public function setName($name)
    {
        $this->name = $name;
    }
}