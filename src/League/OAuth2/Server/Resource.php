<?php
/**
 * OAuth 2.0 Resource Server
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @author      Woody Gilk <woody@shadowhand.me>
 * @copyright   Copyright (c) 2013-2014 PHP League of Extraordinary Packages
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
     * Exception error codes
     * @var array
     */
    protected static $exceptionCodes = array(
        0   =>  'invalid_request',
        1   =>  'invalid_token',
        2   =>  'insufficient_scope',
        3   =>  'missing_token',
    );

    /**
     * Exception error messages
     * @var array
     */
    protected static $exceptionMessages = array(
        'invalid_request'    =>  'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "%s" parameter.',
        'invalid_token'      =>  'The access token provided is expired, revoked, malformed, or invalid for other reasons.',
        'insufficient_scope' =>  'The request requires higher privileges than provided by the access token. Required scopes are: %s.',
        'missing_token'      =>  'The request is missing an access token in either the Authorization header or the %s request parameter.',
    );

    /**
     * Exception error HTTP status codes
     * @var array
     *
     * RFC 6750, section 3.1:
     * When a request fails, the resource server responds using the
     * appropriate HTTP status code (typically, 400, 401, 403, or 405) and
     * includes one of the following error codes in the response:
     */
    protected static $exceptionHttpStatusCodes = array(
        'invalid_request'    =>  400,
        'invalid_token'      =>  401,
        'insufficient_scope' =>  403,
        'missing_token'      =>  400,
    );

    /**
     * Get an exception message
     *
     * @param  string $error The error message key
     * @return string        The error message
     */
    public static function getExceptionMessage($error = '')
    {
        return self::$exceptionMessages[$error];
    }

    /**
     * Get an exception code
     *
     * @param  integer $code The exception code
     * @return string        The exception code type
     */
    public static function getExceptionType($code = 0)
    {
        return self::$exceptionCodes[$code];
    }

        /**
     * Get all headers that have to be send with the error response
     *
     * @param  string $error The error message key
     * @return array         Array with header values
     */
    public static function getExceptionHttpHeaders($error)
    {
        $headers = array();
        switch (self::$exceptionHttpStatusCodes[$error]) {
            case 401:
                $headers[] = 'HTTP/1.1 401 Unauthorized';
                break;
            case 403:
                $headers[] = 'HTTP/1.1 403 Forbidden';
                break;
            case 400:
            default:
                $headers[] = 'HTTP/1.1 400 Bad Request';
        }

        // Add "WWW-Authenticate" header
        //
        // RFC 6749, section 5.2.:
        // "If the client attempted to authenticate via the 'Authorization'
        // request header field, the authorization server MUST
        // respond with an HTTP 401 (Unauthorized) status code and
        // include the "WWW-Authenticate" response header field
        // matching the authentication scheme used by the client.
        // @codeCoverageIgnoreStart
        if ($error === 'invalid_token') {
            $authScheme = null;
            $request = Request::buildFromGlobals();
            if ($request->server('PHP_AUTH_USER') !== null) {
                $authScheme = 'Basic';
            } else {
                $authHeader = $request->header('Authorization');
                if ($authHeader !== null) {
                    if (strpos($authHeader, 'Bearer') === 0) {
                        $authScheme = 'Bearer';
                    } elseif (strpos($authHeader, 'Basic') === 0) {
                        $authScheme = 'Basic';
                    }
                }
            }
            if ($authScheme !== null) {
                $headers[] = 'WWW-Authenticate: '.$authScheme.' realm=""';
            }
        }
        // @codeCoverageIgnoreEnd

        return $headers;
    }

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
        return $this;
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
        return $this;
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

        if (! $result) {
            throw new Exception\InvalidAccessTokenException(self::$exceptionMessages['invalid_token'], 1);
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
     * @param bool          If scopes are required, missing scope will trigger an exception
     * @throws Exception\InsufficientScopeException Thrown if the any of the given scopes are not in the session
     * @return bool         Returns bool if all scopes are found, false if any fail
     */
    public function hasScope($scopes, $required = false)
    {
        if (!is_array($scopes)) {
            $scopes = array($scopes);
        }

        $missing = array_diff($scopes, $this->sessionScopes);

        if ($missing) {
            if ($required) {
                $missing = implode(', ', $missing);
                throw new Exception\InsufficientScopeException(sprintf(self::$exceptionMessages['insufficient_scope'], $missing), 3);
            }
            return false;
        }
        return true;
    }

    /**
     * Reads in the access token from the headers.
     *
     * @param $headersOnly Limit Access Token to Authorization header only
     * @throws Exception\MissingAccessTokenException  Thrown if there is no access token presented
     * @return string
     */
    public function determineAccessToken($headersOnly = false)
    {
        // Try to get it directly from a header
        if (! $header = $this->getRequest()->header('Authorization')) {

            // Failing that try getting it from a server variable
            $header = $this->getRequest()->server('HTTP_AUTHORIZATION');
        }

        // One of them worked
        if ($header) {
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
            throw new Exception\MissingAccessTokenException(sprintf(self::$exceptionMessages['missing_token'], $this->tokenKey), 3);
        }

        return $accessToken;
    }
}
