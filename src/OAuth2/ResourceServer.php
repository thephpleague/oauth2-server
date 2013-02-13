<?php
/**
 * OAuth 2.0 Resource Server
 *
 * @package     lncd/oauth2
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 University of Lincoln
 * @license     http://mit-license.org/
 * @link        http://github.com/lncd/oauth2
 */

namespace OAuth2;

use OutOfBoundsException;
use OAuth2\Storage\SessionInterface;
use OAuth2\Storage\SessionScopeInterface;
use OAuth2\Util\RequestInterface;
use OAuth2\Util\Request;

/**
 * OAuth 2.0 Resource Server
 */
class ResourceServer
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
     * Checks if the access token is valid or not.
     *
     * @throws Exception\InvalidAccessTokenException Thrown if the presented access token is not valid
     * @return bool
     */
    public function isValid()
    {
        $access_token = $this->determineAccessToken();

        $result = $this->storages['session']->validateAccessToken($access_token);

        if ( ! $result) {
            throw new Exception\InvalidAccessTokenException('Access token is not valid');
        }

        $this->accessToken = $access_token;
        $this->sessionId = $result['id'];
        $this->ownerType = $result['owner_type'];
        $this->ownerId = $result['owner_id'];

        $this->sessionScopes = $this->storages['session']->getScopes($this->sessionId);

        return true;
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
     * @throws Exception\MissingAccessTokenException  Thrown if there is no access token presented
     * @return string
     */
    protected function determineAccessToken()
    {
        if ($header = $this->getRequest()->header('Authorization')) {
            $access_token = base64_decode(trim(str_replace('Bearer', '', $header)));
        } else {
            $method = $this->getRequest()->server('REQUEST_METHOD');
            $access_token = $this->getRequest()->{$method}($this->tokenKey);
        }

        if (empty($access_token)) {
            throw new Exception\InvalidAccessTokenException('Access token is missing');
        }

        return $access_token;
    }

}
