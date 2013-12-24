<?php
/**
 * OAuth 2.0 Resource Server
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server;

use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\Storage\AccessTokenInterface;
use League\OAuth2\Server\Storage\ClientInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * OAuth 2.0 Resource Server
 */
class Resource
{
    /**
     * The access token
     *
     * @var League\OAuth2\Server\AccessToken
     */
    protected $accessToken = null;

    /**
     * The session
     *
     * @var \League\OAuth2\Server\Session
     */
    protected $session = null;

    /**
     * The request object
     *
     * @var Util\RequestInterface
     */
    protected $request = null;

    /**
     * The query string key which is used by clients to present the access token (default: access_token)
     *
     * @var string
     */
    protected $tokenKey = 'access_token';

    /**
     * The client ID
     *
     * @var League\OAuth2\Server\Client
     */
    protected $client = null;

    /**
     * Session storage
     *
     * @var League\OAuth2\Server\Storage\SessionInterface
     */
    protected $sessionStorage = null;

    /**
     * Access token storage
     *
     * @var League\OAuth2\Server\Storage\AccessTokenInterface
     */
    protected $accessTokenStorage = null;

    /**
     * Client storage
     *
     * @var League\OAuth2\Server\Storage\ClientInterface
     */
    protected $clientStorage = null;

    /**
     * Initialise the resource server
     *
     * @param SessionInterface    $sessionStorage     [description]
     * @param AccessTokenInteface $accessTokenStorage [description]
     * @param ClientInterface     $clientStorage      [description]
     *
     * @return self
     */
    public function __construct(
        SessionInterface $sessionStorage,
        AccessTokenInteface $accessTokenStorage,
        ClientInterface $clientStorage
    ) {
        $this->sessionStorage = $sessionStorage;
        $this->accessTokenStorage = $accessTokenStorage;
        $this->clientStorage = $clientStorage;
        return $this;
    }

    /**
     * Sets the Request Object
     *
     * @param \Symfony\Component\HttpFoundation\Request The Request Object
     *
     * @return self
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;
        return $this;
    }

    /**
     * Gets the Request object. It will create one from the globals if one is not set.
     *
     * @return \Symfony\Component\HttpFoundation\Request
     */
    public function getRequest()
    {
        if ($this->request = null) {
            return Symfony\Component\HttpFoundation\Request::createFromGlobals();
        }

        return $this->request;
    }

    /**
     * Returns the query string key for the access token.
     *
     * @return string
     */
    public function getTokenKey()
    {
        return $this->tokenKey;
    }

    /**
     * Sets the query string key for the access token.
     *
     * @param $key The new query string key
     *
     * @return self
     */
    public function setTokenKey($key)
    {
        $this->tokenKey = $key;
        return $this;
    }

    /**
     * Gets the access token owner ID
     *
     * @return string
     */
    public function getOwnerId()
    {
        return $this->session->getOwnerId();
    }

    /**
     * Gets the owner type
     *
     * @return string
     */
    public function getOwnerType()
    {
        return $this->session->getOwnerType();
    }

    /**
     * Gets the access token
     *
     * @return string
     */
    public function getAccessToken()
    {
        return $this->accessToken->getId();
    }

    /**
     * Gets the client ID that created the session
     *
     * @return string
     */
    public function getClientId()
    {
        return $this->client->getId();
    }

    /**
     * Checks if the access token is valid or not
     *
     * @param $headersOnly Limit Access Token to Authorization header only
     *
     * @return bool
     */
    public function isValid($headersOnly = false)
    {
        try {
            $accessToken = $this->determineAccessToken($headersOnly);
        } catch (Exception $e) {
            return false;
        }

        // Set the access token
        $tokenResult = $this->accessTokenStorage->getToken($accessToken);
        if ($tokenResult === null) {
            return false;
        }

        $accessToken = new AccessToken;
        $accessToken->setId($token);
        $accessToken->setTTL($tokenResult['ttl']);
        $accessToken->setTimestamp($tokenResult['created']);

        $scopes = $this->accessTokenStorage->getTokenScopes($token);
        foreach ($scopes as $scope => $details) {
            $accessToken->associateScope($scope, $details);
        }

        $this->accessToken = $accessToken;

        // Set the session
        $sessionResult = $this->sessionStorage->getSession($tokenResult['session_id']);
        if ($sessionResult === null) {
            return false;
        }

        $session = new Session();
        $session->setOwner($sessionResult['owner_type'], $sessionResult['owner_id']);

        $this->session = $session;

        // Set the client
        $clientResult = $this->clientStorage->getClient($sessionResult['client_id']);
        if ($clientResult === null) {
            return false;
        }

        $client = new Client();
        $client->setCredentials($clientResult['client_id'], $clientResult['client_secret']);

        $this->client = $client;

        return true;
    }

    /**
     * Get the session scopes
     *
     * @return array
     */
    public function getScopes()
    {
        return $this->accessToken->getScopes();
    }

    /**
     * Checks if the presented access token has the given scope(s)
     *
     * @param array|string  An array of scopes or a single scope as a string
     *
     * @return bool         Returns bool if all scopes are found, false if any fail
     */
    public function hasScope($scopes)
    {
        if (is_string($scopes)) {
            return $this->accessToken->hasScope($scopes);
        } elseif (is_array($scopes)) {
            foreach ($scopes as $scope) {
                if (!$this->accessToken->hasScope($scope)) {
                    return false;
                }
            }
            return true;
        }
    }

    /**
     * Reads in the access token from the headers
     *
     * @param $headersOnly Limit Access Token to Authorization header only
     *
     * @throws Exception\MissingAccessTokenException  Thrown if there is no access token presented
     *
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
