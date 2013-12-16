<?php

namespace League\OAuth2\Server;

use OutOfBoundsException;
use League\OAuth2\Server\Exception\OAuth2Exception;
use League\OAuth2\Server\Storage\SessionStorageInterface;
use Symfony\Component\HttpFoundation\ParameterBag;

class Session
{
    protected $id = null;

    protected $clientId = null;

    protected $ownerId = null;

    protected $ownerType = null;

    protected $authCode = null;

    protected $accessToken = null;

    protected $refreshToken = null;

    /**
     * Session scopes
     * @var \Symfony\Component\HttpFoundation\ParameterBag
     */
    protected $scopes = null;

    protected $storage = null;

    public function __construct(SessionStorageInterface $storage)
    {
        $this->storage = $storage;
        $this->scopes = new ParameterBag();
    }

    public function associateScope($scope)
    {
        if (!$this->scopes->has($scope)) {
            $this->scopes->set($scope, 1);
        }

        return $this;
    }

    public function hasScope($scope)
    {
        return $this->scopes->has($scope);
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
     * Set client
     * @param League\OAuth2\Server\Client
     */
    public function setClient(Client $client)
    {
        $this->client = $client;
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

    public function getOwnerId()
    {
        return $this->ownerId;
    }

    public function getOwnerType()
    {
        return $this->ownerType;
    }

    public function getById($id)
    {
        $params = $this->storage->getSession($id);

        if ($params === null) {
            throw new OAuth2Exception('Unrecognised session ID - ' . $id);
        }

        $this->id = $params['session_id'];
        $this->setOwner($params['owner_type'], $params['owner_id']);
    }
}
