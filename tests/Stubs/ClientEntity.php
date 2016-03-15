<?php

namespace LeagueTests\Stubs;

use League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;

class ClientEntity implements ClientEntityInterface
{
    use EntityTrait;

    /**
     * @var string
     */
    protected $name;

    /**
     * @var string
     */
    protected $secret;

    /**
     * @var string
     */
    protected $redirectUri;

    /**
     * {@inheritdoc}
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * {@inheritdoc}
     */
    public function setName($name)
    {
        $this->name = $name;
    }

    /**
     * {@inheritdoc}
     */
    public function canKeepASecret()
    {
        return $this->secret !== null;
    }

    /**
     * {@inheritdoc}
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }

    /**
     * {@inheritdoc}
     */
    public function validateSecret($submittedSecret)
    {
        return strcmp((string) $submittedSecret, $this->secret) === 0;
    }

    /**
     * {@inheritdoc}
     */
    public function setRedirectUri($redirectUri)
    {
        $this->redirectUri = $redirectUri;
    }

    /**
     * {@inheritdoc}
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }
}
