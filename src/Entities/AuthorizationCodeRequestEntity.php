<?php

namespace League\OAuth2\Server\Entities;

class AuthorizationCodeRequestEntity
{
    /**
     * @var string
     */
    private $clientId;

    /**
     * @var null|string
     */
    private $redirectUri;

    /**
     * @var null|string
     */
    private $scope;

    /**
     * @var null|string
     */
    private $state;

    /**
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * @return null|string
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * @return null|string
     */
    public function getScope()
    {
        return $this->scope;
    }

    /**
     * @return null|string
     */
    public function getState()
    {
        return $this->state;
    }

    /**
     * AuthorizationCodeRequestEntity constructor.
     *
     * @param string      $clientId
     * @param string|null $redirectUri
     * @param string|null $scope
     * @param string|null $state
     */
    public function __construct($clientId, $redirectUri = null, $scope = null, $state = null)
    {
        $this->clientId = $clientId;
        $this->redirectUri = $redirectUri;
        $this->scope = $scope;
        $this->state = $state;
    }

    public function __sleep()
    {
        return ['clientId', 'redirectUri', 'scope', 'state'];
    }
}
