<?php
/**
 * OAuth 2.0 Resource Server
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server;

use League\OAuth2\Server\Storage\StorageWrapper;
use League\OAuth2\Server\Storage\ClientInterface;
use League\OAuth2\Server\Storage\AccessTokenInterface;
use League\OAuth2\Server\Storage\AuthCodeInterface;
use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\Storage\ScopeInterface;
use League\OAuth2\Server\Entity\AccessToken;
use Symfony\Component\HttpFoundation\Request;

/**
 * OAuth 2.0 Resource Server
 */
class Resource extends AbstractServer
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
     * @param SessionInterface    $sessionStorage
     * @param AccessTokenInteface $accessTokenStorage
     * @param ClientInterface     $clientStorage
     * @param ScopeInterface      $scopeStorage
     * @return self
     */
    public function __construct(
        SessionInterface $sessionStorage,
        AccessTokenInterface $accessTokenStorage,
        ClientInterface $clientStorage,
        ScopeInterface $scopeStorage
    ) {
        $this->setStorage('session', $sessionStorage);
        $this->setStorage('access_token', $accessTokenStorage);
        $this->setStorage('client', $clientStorage);
        $this->setStorage('scope', $scopeStorage);

        return $this;
    }

    /**
     * Set the storage
     * @param  string $type Storage type
     * @param mixed $storage Storage class
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
    public function getTokenKey()
    {
        return $this->tokenKey;
    }

    /**
     * Sets the query string key for the access token.
     * @param $key The new query string key
     * @return self
     */
    public function setTokenKey($key)
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
        return $this->accessToken->getToken();
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
     * Checks if the access token is valid or not
     * @param $headersOnly Limit Access Token to Authorization header only
     * @return bool
     */
    public function isValid($headersOnly = false)
    {
        try {
            $accessTokenString = $this->determineAccessToken($headersOnly);
        } catch (\Exception $e) {
            return false;
        }

        // Set the access token
        $this->accessToken = $this->storages['access_token']->get($accessTokenString);
        return ($this->accessToken instanceof AccessToken);
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
     * @param array|string $scopes An array of scopes or a single scope as a string
     * @return bool Returns bool if all scopes are found, false if any fail
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
     * Reads in the access token from the headers
     * @param $headersOnly Limit Access Token to Authorization header only
     * @throws Exception\MissingAccessTokenException  Thrown if there is no access token presented
     * @return string
     */
    public function determineAccessToken($headersOnly = false)
    {
        if ($header = $this->getRequest()->headers->get('Authorization')) {
            // Check for special case, because cURL sometimes does an
            // internal second request and doubles the authorization header,
            // which always resulted in an error.
            //
            // 1st request: Authorization: Bearer XXX
            // 2nd request: Authorization: Bearer XXX, Bearer XXX
            if (strpos($header, ',') !== false) {
                $headerPart = explode(',', $header);
                $accessToken = trim(preg_replace('/^(?:\s+)?Bearer\s/', '', $headerPart[0]));
            } else {
                $accessToken = trim(preg_replace('/^(?:\s+)?Bearer\s/', '', $header));
            }
            $accessToken = ($accessToken === 'Bearer') ? '' : $accessToken;
        } elseif ($headersOnly === false) {
            $accessToken = $this->getRequest()->request->get($this->tokenKey);
        }

        if (empty($accessToken)) {
            throw new Exception\InvalidAccessTokenException('Access token is missing');
        }

        return $accessToken;
    }
}
