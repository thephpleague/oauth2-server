<?php
/**
 * OAuth 2.0 session entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Entities;

use League\OAuth2\Server\Exception\OAuth2Exception;
use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\Exception\ServerException;
use League\OAuth2\Server\Authorization;
use League\OAuth2\Server\Resource;
use Symfony\Component\HttpFoundation\ParameterBag;

/**
 * Session entity grant
 */
class Session
{
    /**
     * Session identifier
     * @var string
     */
    protected $id;

    /**
     * Client identifier
     * @var string
     */
    protected $clientId;

    /**
     * Session owner identifier
     * @var string
     */
    protected $ownerId;

    /**
     * Session owner type (e.g. "user")
     * @var string
     */
    protected $ownerType;

    /**
     * Auth code
     * @var \League\OAuth2\Server\Entities\AuthCode
     */
    protected $authCode;

    /**
     * Access token
     * @var \League\OAuth2\Server\Entities\AccessToken
     */
    protected $accessToken;

    /**
     * Refresh token
     * @var \League\OAuth2\Server\Entities\RefreshToken
     */
    protected $refreshToken;

    /**
     * Session scopes
     * @var \Symfony\Component\HttpFoundation\ParameterBag
     */
    protected $scopes;

    /**
     * Authorization or resource server
     * @var \League\OAuth2\Server\Authorization|\League\OAuth2\Server\Resource
     */
    protected $server;

    /**
     * __construct
     * @param \League\OAuth2\Server\Authorization|\League\OAuth2\Server\Resource $server
     * @return self
     */
    public function __construct($server)
    {
        if (! $server instanceof Authorization && ! $server instanceof Resource) {
            throw new ServerException('No instance of Authorization or Resource server injected');
        }

        $this->scopes = new ParameterBag();
        return $this;
    }

    /**
     * Set the session identifier
     * @param string $id
     * @return self
     */
    public function setId($id)
    {
        $this->id = $id;
        return $this;
    }

    /**
     * Return the session identifier
     * @return string
     */
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

    /**
     * Return all scopes associated with the session
     * @return array Array of \League\OAuth2\Server\Entities\Scope
     */
    public function getScopes()
    {
        return $this->scopes->all();
    }

    /**
     * Associate an access token with the session
     * @param  \League\OAuth2\Server\Entities\AccessToken $accessToken
     * @return self
     */
    public function associateAccessToken(AccessToken $accessToken)
    {
        $this->accessToken = $accessToken;
        return $this;
    }

    /**
     * Associate a refresh token with the session
     * @param  \League\OAuth2\Server\Entities\RefreshToken $refreshToken
     * @return self
     */
    public function associateRefreshToken(RefreshToken $refreshToken)
    {
        $this->refreshToken = $refreshToken;
        return $this;
    }

    /**
     * Associate an authorization code with the session
     * @param  \League\OAuth2\Server\Entities\AuthCode $authCode
     * @return self
     */
    public function associateAuthCode(AuthCode $authCode)
    {
        $this->authCode = $authCode;
        return $this;
    }

    /**
     * Associate a client with the session
     * @param  League\OAuth2\Server\Entities\Client $client The client
     * @return self
     */
    public function associateClient(Client $client)
    {
        $this->client = $client;
        return $this;
    }

    /**
     * Return the session client
     * @return League\OAuth2\Server\Entities\Client
     */
    public function getClient()
    {
        return $this->client;
    }

    /**
     * Set the session owner
     * @param string $type The type of the owner (e.g. user, app)
     * @param string $id   The identifier of the owner
     * @return self
     */
    public function setOwner($type, $id)
    {
        $this->ownerType = $type;
        $this->ownerId = $id;

        return $this;
    }

    /**
     * Return session owner identifier
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

    /**
     * Save the session
     * @return void
     */
    public function save()
    {
        // Save the session and get an identifier
        $id = $this->server->getStorage('session')->createSession(
            $this->getOwnerType(),
            $this->getOwnerId(),
            $this->getClient()->getId(),
            $this->getClient()->getRedirectUri()
        );

        $this->setId($id);

        // Associate the scope with the session
        foreach ($this->getScopes() as $scope) {
            $this->server->getStorage('session')->associateScope($this->getId(), $scope->getId());
        }
    }
}
