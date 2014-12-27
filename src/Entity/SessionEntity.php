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
class SessionEntity implements SessionInterface
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
     * {@inheritDoc}
     */
    public function setId($id)
    {
        $this->id = $id;

        return $this;
    }

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
    public function associateScope(ScopeInterface $scope)
    {
        if (!isset($this->scopes[$scope->getId()])) {
            $this->scopes[$scope->getId()] = $scope;
        }

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function hasScope($scope)
    {
        if ($this->scopes === null) {
            $this->getScopes();
        }

        return isset($this->scopes[$scope]);
    }

    /**
     * {@inheritDoc}
     */
    public function getScopes()
    {
        if ($this->scopes === null) {
            $this->scopes = $this->formatScopes($this->server->getSessionStorage()->getScopes($this));
        }

        return $this->scopes;
    }

    /**
     * {@inheritDoc}
     */
    private function formatScopes($unformatted = [])
    {
        $scopes = [];
        if (is_array($unformatted)) {
            foreach ($unformatted as $scope) {
                if ($scope instanceof ScopeInterface) {
                    $scopes[$scope->getId()] = $scope;
                }
            }
        }

        return $scopes;
    }

    /**
     * {@inheritDoc}
     */
    public function associateAccessToken(AccessTokenInterface $accessToken)
    {
        $this->accessToken = $accessToken;
    }

    /**
     * {@inheritDoc}
     */
    public function associateRefreshToken(RefreshTokenInterface $refreshToken)
    {
        $this->refreshToken = $refreshToken;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function associateClient(ClientInterface $client)
    {
        $this->client = $client;

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getClient()
    {
        if ($this->client instanceof ClientInterface) {
            return $this->client;
        }

        $this->client = $this->server->getClientStorage()->getBySession($this);

        return $this->client;
    }

    /**
     * {@inheritDoc}
     */
    public function setOwner($type, $id)
    {
        $this->ownerType = $type;
        $this->ownerId = $id;

        $this->server->getEventEmitter()->emit(new SessionOwnerEvent($this));

        return $this;
    }

    /**
     * {@inheritDoc}
     */
    public function getOwnerId()
    {
        return $this->ownerId;
    }

    /**
     * {@inheritDoc}
     */
    public function getOwnerType()
    {
        return $this->ownerType;
    }

    /**
     * {@inheritDoc}
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
