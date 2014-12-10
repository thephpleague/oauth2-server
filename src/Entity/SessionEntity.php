<?php
/**
 * OAuth 2.0 session entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entity;

use League\OAuth2\Server\AbstractServer;
use League\OAuth2\Server\Event\SessionOwnerEvent;

/**
 * Session entity grant
 */
class SessionEntity
{
    /**
     * Session identifier
     *
     * @var string
     */
    protected $id;

    /**
     * Client identifier
     *
     * @var \League\OAuth2\Server\Entity\ClientEntity
     */
    protected $client;

    /**
     * Session owner identifier
     *
     * @var string
     */
    protected $ownerId;

    /**
     * Session owner type (e.g. "user")
     *
     * @var string
     */
    protected $ownerType;

    /**
     * Auth code
     *
     * @var \League\OAuth2\Server\Entity\AuthCodeEntity
     */
    protected $authCode;

    /**
     * Access token
     *
     * @var \League\OAuth2\Server\Entity\AccessTokenEntity
     */
    protected $accessToken;

    /**
     * Refresh token
     *
     * @var \League\OAuth2\Server\Entity\RefreshTokenEntity
     */
    protected $refreshToken;

    /**
     * Session scopes
     *
     * @var \Symfony\Component\HttpFoundation\ParameterBag
     */
    protected $scopes;

    /**
     * Authorization or resource server
     *
     * @var \League\OAuth2\Server\AuthorizationServer|\League\OAuth2\Server\ResourceServer
     */
    protected $server;

    /**
     * __construct
     *
     * @param \League\OAuth2\Server\AbstractServer $server
     *
     * @return self
     */
    public function __construct(AbstractServer $server)
    {
        $this->server = $server;

        return $this;
    }

    /**
     * Set the session identifier
     *
     * @param string $id
     *
     * @return self
     */
    public function setId($id)
    {
        $this->id = $id;

        return $this;
    }

    /**
     * Return the session identifier
     *
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Associate a scope
     *
     * @param \League\OAuth2\Server\Entity\ScopeEntity $scope
     *
     * @return self
     */
    public function associateScope(ScopeEntity $scope)
    {
        if (!isset($this->scopes[$scope->getId()])) {
            $this->scopes[$scope->getId()] = $scope;
        }

        return $this;
    }

    /**
     * Check if access token has an associated scope
     *
     * @param string $scope Scope to check
     *
     * @return bool
     */
    public function hasScope($scope)
    {
        if ($this->scopes === null) {
            $this->getScopes();
        }

        return isset($this->scopes[$scope]);
    }

    /**
     * Return all scopes associated with the session
     *
     * @return \League\OAuth2\Server\Entity\ScopeEntity[]
     */
    public function getScopes()
    {
        if ($this->scopes === null) {
            $this->scopes = $this->formatScopes($this->server->getSessionStorage()->getScopes($this));
        }

        return $this->scopes;
    }

    /**
     * Format the local scopes array
     *
     * @param  \League\OAuth2\Server\Entity\Scope[]
     *
     * @return array
     */
    private function formatScopes($unformatted = [])
    {
        $scopes = [];
        if (is_array($unformatted)) {
            foreach ($unformatted as $scope) {
                if ($scope instanceof ScopeEntity) {
                    $scopes[$scope->getId()] = $scope;
                }
            }
        }

        return $scopes;
    }

    /**
     * Associate an access token with the session
     *
     * @param \League\OAuth2\Server\Entity\AccessTokenEntity $accessToken
     *
     * @return self
     */
    public function associateAccessToken(AccessTokenEntity $accessToken)
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    /**
     * Associate a refresh token with the session
     *
     * @param \League\OAuth2\Server\Entity\RefreshTokenEntity $refreshToken
     *
     * @return self
     */
    public function associateRefreshToken(RefreshTokenEntity $refreshToken)
    {
        $this->refreshToken = $refreshToken;

        return $this;
    }

    /**
     * Associate a client with the session
     *
     * @param \League\OAuth2\Server\Entity\ClientEntity $client The client
     *
     * @return self
     */
    public function associateClient(ClientEntity $client)
    {
        $this->client = $client;

        return $this;
    }

    /**
     * Return the session client
     *
     * @return \League\OAuth2\Server\Entity\ClientEntity
     */
    public function getClient()
    {
        if ($this->client instanceof ClientEntity) {
            return $this->client;
        }

        $this->client = $this->server->getClientStorage()->getBySession($this);

        return $this->client;
    }

    /**
     * Set the session owner
     *
     * @param string $type The type of the owner (e.g. user, app)
     * @param string $id   The identifier of the owner
     *
     * @return self
     */
    public function setOwner($type, $id)
    {
        $this->ownerType = $type;
        $this->ownerId = $id;

        $this->server->getEventEmitter()->emit(new SessionOwnerEvent($this));

        return $this;
    }

    /**
     * Return session owner identifier
     *
     * @return string
     */
    public function getOwnerId()
    {
        return $this->ownerId;
    }

    /**
     * Return session owner type
     *
     * @return string
     */
    public function getOwnerType()
    {
        return $this->ownerType;
    }

    /**
     * Save the session
     *
     * @return void
     */
    public function save()
    {
        // Save the session and get an identifier
        $id = $this->server->getSessionStorage()->create(
            $this->getOwnerType(),
            $this->getOwnerId(),
            $this->getClient()->getId(),
            $this->getClient()->getRedirectUri()
        );

        $this->setId($id);

        // Associate the scope with the session
        foreach ($this->getScopes() as $scope) {
            $this->server->getSessionStorage()->associateScope($this, $scope);
        }
    }
}
