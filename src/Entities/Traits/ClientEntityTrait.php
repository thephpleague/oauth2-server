<?php
namespace League\OAuth2\Server\Entities\Traits;

trait ClientEntityTrait
{
    /**
     * @var string
     */
    protected $secret;

    /**
     * @var string
     */
    protected $name;

    /**
     * Get the client's secret
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }

    /**
     * Set the client's secret
     * @param string $secret
     * @return string
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }

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