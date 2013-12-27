<?php

namespace League\OAuth2\Server\Entities;

use OutOfBoundsException;
use League\OAuth2\Server\Exception\OAuth2Exception;
use League\OAuth2\Server\Storage\SessionInterface;
use Symfony\Component\HttpFoundation\ParameterBag;

class Session
{
    /**
     * Session ID
     * @var string
     */
    protected $id = null;

    protected $clientId = null;

    protected $ownerId = null;

    protected $ownerType = null;

    protected $authCode = null;

    protected $accessToken = null;

    protected $refreshToken = null;

    /**
     * Session storage
     * @var \League\OAuth2\Server\Storage\SessionInterface
     */
    protected $storage = null;

    /**
     * Session scopes
     * @var \Symfony\Component\HttpFoundation\ParameterBag
     */
    protected $scopes = null;

    /**
     * Constuctor
     * @param SessionInterface $storage
     * @return self
     */
    public function __construct(SessionInterface $storage)
    {
        $this->storage = $storage;
        $this->scopes = new ParameterBag();
        return $this;
    }

    /**
     * Get storage
     * @return SessionInterface
     */
    public function getStorage()
    {
        return $this->storage;
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

    /**
     * Associate a scope
     * @param \League\OAuth2\Server\Entities\Scope $scope
     * @return self
     */
    public function associateScope($scope)
    {
        if (!$this->scopes->has($scope->getId())) {
            $this->scopes->set($scope->getId(), $scope);
        }

        return $this;
    }

    /**
     * Check if access token has an associated scope
     * @param string $scope Scope to check
     * @return bool
     */
    public function hasScope($scope)
    {
        return $this->scopes->has($scope);
    }

    public function getScopes()
    {
        return $this->scopes;
    }

    public function associateAccessToken(AccessToken $accessToken)
    {
        $this->accessToken = $accessToken;
    }

    public function associateRefreshToken(RefreshToken $refreshToken)
    {
        $this->refreshToken = $refreshToken;
    }

    public function associateAuthCode(AuthCode $authCode)
    {
        $this->authCode = $authCode;
    }

    /**
     * Associate a client
     * @param  League\OAuth2\Server\Client $client The client
     * @return self
     */
    public function associateClient(Client $client)
    {
        $this->client = $client;

        return $this;
    }

    /**
     * Return client
     * @return League\OAuth2\Server\Client
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * Set the session owner
     * @param string $type The type of the owner (e.g. user, app)
     * @param string $id   The ID of the owner
     * @return self
     */
    public function setOwner($type, $id)
    {
        $this->ownerType = $type;
        $this->ownerId = $id;

        return $this;
    }

    /**
     * Return session owner ID
     * @return string
     */
    public function getOwnerId()
    {
        return $this->ownerId;
    }

    /**
     * Return session owner type
     * @return string
     */
    public function getOwnerType()
    {
        return $this->ownerType;
    }

    public function save()
    {
        // Save the session and get an ID
        $id = $this->getStorage()->createSession(
            $this->getOwnerType(),
            $this->getOwnerId(),
            $this->getClient()->getId(),
            $this->getClient()->getRedirectUri()
        );

        $this->setId($id);

        // Associate the scope with the session
        foreach ($this->getScopes() as $scope) {
            $this->getStorage()->associateScope($this->getId(), $scope->getId());
        }
    }
}
