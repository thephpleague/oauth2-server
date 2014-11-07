<?php
/**
 * OAuth 2.0 Resource Server
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server;

use League\OAuth2\Server\Storage\ClientInterface;
use League\OAuth2\Server\Storage\AccessTokenInterface;
use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\Storage\ScopeInterface;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\TokenType\Bearer;
use League\OAuth2\Server\Exception;
use Symfony\Component\HttpFoundation\Request;

/**
 * OAuth 2.0 Resource Server
 */
class ResourceServer extends AbstractServer
{
    /**
     * The access token
     * @var League\OAuth2\Server\AccessToken
     */
    protected $accessToken;

    /**
     * The query string key which is used by clients to present the access token (default: access_token)
     * @var string
     */
    protected $tokenKey = 'access_token';

    /**
     * Initialise the resource server
     * @param  SessionInterface    $sessionStorage
     * @param  AccessTokenInteface $accessTokenStorage
     * @param  ClientInterface     $clientStorage
     * @param  ScopeInterface      $scopeStorage
     * @return self
     */
    public function __construct(
        SessionInterface $sessionStorage,
        AccessTokenInterface $accessTokenStorage,
        ClientInterface $clientStorage,
        ScopeInterface $scopeStorage
    ) {
        $sessionStorage->setServer($this);
        $this->setStorage('session', $sessionStorage);

        $accessTokenStorage->setServer($this);
        $this->setStorage('access_token', $accessTokenStorage);

        $clientStorage->setServer($this);
        $this->setStorage('client', $clientStorage);

        $scopeStorage->setServer($this);
        $this->setStorage('scope', $scopeStorage);

        // Set Bearer as the default token type
        $this->setTokenType(new Bearer);

        parent::__construct();

        return $this;
    }

    /**
     * Set the storage
     * @param  string $type    Storage type
     * @param  mixed  $storage Storage class
     * @return self
     */
    protected function setStorage($type, $storage)
    {
        $storage->setServer($this);
        $this->storages[$type] = $storage;

        return $this;
    }

    /**
     * Returns the query string key for the access token.
     * @return string
     */
    public function getIdKey()
    {
        return $this->tokenKey;
    }

    /**
     * Sets the query string key for the access token.
     * @param $key The new query string key
     * @return self
     */
    public function setIdKey($key)
    {
        $this->tokenKey = $key;

        return $this;
    }

    /**
     * Gets the access token owner ID
     * @return string
     */
    public function getOwnerId()
    {
        return $this->accessToken->getSession()->getOwnerId();
    }

    /**
     * Gets the owner type
     * @return string
     */
    public function getOwnerType()
    {
        return $this->accessToken->getSession()->getOwnerType();
    }

    /**
     * Gets the access token
     * @return string
     */
    public function getAccessToken()
    {
        return $this->accessToken->getId();
    }

    /**
     * Gets the client ID that created the session
     * @return string
     */
    public function getClientId()
    {
        return $this->accessToken->getSession()->getClient()->getId();
    }

    /**
     * Get the session scopes
     * @return array
     */
    public function getScopes()
    {
        return $this->accessToken->getScopes();
    }

    /**
     * Checks if the presented access token has the given scope(s)
     * @param  array|string $scopes An array of scopes or a single scope as a string
     * @return bool         Returns bool if all scopes are found, false if any fail
     */
    public function hasScope($scopes)
    {
        if (is_string($scopes)) {
            return $this->accessToken->hasScope($scopes);
        }

        if (is_array($scopes)) {
            foreach ($scopes as $scope) {
                if (!$this->accessToken->hasScope($scope)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * Checks if the access token is valid or not
     * @param $headersOnly Limit Access Token to Authorization header only
     * @return bool
     */
    public function isValidRequest($headersOnly = true, $accessToken = null)
    {
        $accessTokenString = ($accessToken !== null)
                                ? $accessToken
                                : $this->determineAccessToken($headersOnly);

        // Set the access token
        $this->accessToken = $this->storages['access_token']->get($accessTokenString);

        if (!$this->accessToken instanceof AccessTokenEntity) {
            throw new Exception\AccessDeniedException;
        }

        return true;
    }

    /**
     * Reads in the access token from the headers
     * @param $headersOnly Limit Access Token to Authorization header only
     * @throws Exception\MissingAccessTokenException Thrown if there is no access token presented
     * @return string
     */
    public function determineAccessToken($headersOnly = false)
    {
        if ($this->getRequest()->headers->get('Authorization') !== null) {
            $accessToken = $this->getTokenType()->determineAccessTokenInHeader($this->getRequest());
        } elseif ($headersOnly === false) {
            $accessToken = ($this->getRequest()->server->get('REQUEST_METHOD') === 'GET')
                                ? $this->getRequest()->query->get($this->tokenKey)
                                : $this->getRequest()->request->get($this->tokenKey);
        }

        if (empty($accessToken)) {
            throw new Exception\InvalidRequestException('access token');
        }

        return $accessToken;
    }
}
