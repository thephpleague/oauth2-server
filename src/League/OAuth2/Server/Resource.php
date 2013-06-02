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

use OutOfBoundsException;
use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\Util\RequestInterface;
use League\OAuth2\Server\Util\Request;

/**
 * OAuth 2.0 Resource Server
 */
class Resource
{
    /**
     * The access token
     * @var string
     */
    protected $accessToken = null;

    /**
     * The session ID
     * @var string
     */
    protected $sessionId = null;

    /**
     * The type of the owner of the access token
     * @var string
     */
    protected $ownerType = null;

    /**
     * The ID of the owner of the access token
     * @var string
     */
    protected $ownerId = null;

    /**
     * The scopes associated with the access token
     * @var array
     */
    protected $sessionScopes = array();

    /**
     * The client, scope and session storage classes
     * @var array
     */
    protected $storages = array();

    /**
     * The request object
     * @var Util\RequestInterface
     */
    protected $request = null;

    /**
     * The query string key which is used by clients to present the access token (default: access_token)
     * @var string
     */
    protected $tokenKey = 'access_token';

    /**
     * The client ID
     * @var string
     */
    protected $clientId = null;

    /**
     * Sets up the Resource
     *
     * @param SessionInterface  The Session Storage Object
     */
    public function __construct(SessionInterface $session)
    {
        $this->storages['session'] = $session;
    }

    /**
     * Sets the Request Object
     *
     * @param  RequestInterface The Request Object
     */
    public function setRequest(RequestInterface $request)
    {
        $this->request = $request;
    }

    /**
     * Gets the Request object.  It will create one from the globals if one is not set.
     *
     * @return Util\RequestInterface
     */
    public function getRequest()
    {
        if ($this->request === null) {
            // @codeCoverageIgnoreStart
            $this->request = Request::buildFromGlobals();
        }
        // @codeCoverageIgnoreEnd

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
     */
    public function setTokenKey($key)
    {
        $this->tokenKey = $key;
    }

    /**
     * Gets the access token owner ID.
     *
     * @return string
     */
    public function getOwnerId()
    {
        return $this->ownerId;
    }

    /**
     * Gets the owner type.
     *
     * @return string
     */
    public function getOwnerType()
    {
        return $this->ownerType;
    }

    /**
     * Gets the access token.
     *
     * @return string
     */
    public function getAccessToken()
    {
        return $this->accessToken;
    }

    /**
     * Gets the client ID that created the session
     * @return string
     */
    public function getClientId()
    {
        return $this->clientId;
    }

    /**
     * Checks if the access token is valid or not.
     *
     * @param $headersOnly Limit Access Token to Authorization header only
     * @throws Exception\InvalidAccessTokenException Thrown if the presented access token is not valid
     * @return bool
     */
    public function isValid($headersOnly = false)
    {
        $accessToken = $this->determineAccessToken($headersOnly);

        $result = $this->storages['session']->validateAccessToken($accessToken);

        if ( ! $result) {
            throw new Exception\InvalidAccessTokenException('Access token is not valid');
        }

        $this->accessToken = $accessToken;
        $this->sessionId = $result['session_id'];
        $this->clientId = $result['client_id'];
        $this->ownerType = $result['owner_type'];
        $this->ownerId = $result['owner_id'];

        $sessionScopes = $this->storages['session']->getScopes($this->accessToken);
        foreach ($sessionScopes as $scope) {
            $this->sessionScopes[] = $scope['scope'];
        }

        return true;
    }

    /**
     * Get the session scopes
     * @return array
     */
    public function getScopes()
    {
        return $this->sessionScopes;
    }

    /**
     * Checks if the presented access token has the given scope(s).
     *
     * @param array|string  An array of scopes or a single scope as a string
     * @return bool         Returns bool if all scopes are found, false if any fail
     */
    public function hasScope($scopes)
    {
        if (is_string($scopes)) {
            if (in_array($scopes, $this->sessionScopes)) {
                return true;
            }
            return false;
        } elseif (is_array($scopes)) {
            foreach ($scopes as $scope) {
                if ( ! in_array($scope, $this->sessionScopes)) {
                    return false;
                }
            }
            return true;
        }

        return false;
    }

    /**
     * Reads in the access token from the headers.
     *
     * @param $headersOnly Limit Access Token to Authorization header only
     * @throws Exception\MissingAccessTokenException  Thrown if there is no access token presented
     * @return string
     */
    protected function determineAccessToken($headersOnly = false)
    {
        if ($header = $this->getRequest()->header('Authorization')) {
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
            $method = $this->getRequest()->server('REQUEST_METHOD');
            $accessToken = $this->getRequest()->{$method}($this->tokenKey);
        }

        if (empty($accessToken)) {
            throw new Exception\InvalidAccessTokenException('Access token is missing');
        }

        return $accessToken;
    }

}
