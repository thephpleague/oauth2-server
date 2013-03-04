<?php
/**
 * OAuth 2.0 Authorization Server
 *
 * @package     lncd/oauth2
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 University of Lincoln
 * @license     http://mit-license.org/
 * @link        http://github.com/lncd/oauth2
 */

namespace OAuth2;

use OAuth2\Util\Request;
use OAuth2\Util\SecureKey;
use OAuth2\Storage\SessionInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\Storage\ScopeInterface;
use OAuth2\Grant\GrantTypeInterface;

/**
 * OAuth 2.0 authorization server class
 */
class AuthServer
{
    /**
     * The delimeter between scopes specified in the scope query string parameter
     *
     * The OAuth 2 specification states it should be a space but that is stupid
     * and everyone excepted Google use a comma instead.
     *
     * @var string
     */
    protected $scopeDelimeter = ',';

    /**
     * The TTL (time to live) of an access token in seconds (default: 3600)
     * @var integer
     */
    static protected $expiresIn = 3600;

    /**
     * The registered grant response types
     * @var array
     */
    protected $responseTypes = array();

    /**
     * The client, scope and session storage classes
     * @var array
     */
    static protected $storages = array();

    /**
     * The registered grant types
     * @var array
     */
    static protected $grantTypes = array();

    /**
     * Require the "scope" parameter to be in checkAuthoriseParams()
     * @var boolean
     */
    protected $requireScopeParam = true;

    /**
     * Require the "state" parameter to be in checkAuthoriseParams()
     * @var boolean
     */
    protected $requireStateParam = false;

    /**
     * The request object
     * @var Util\RequestInterface
     */
    static protected $request = null;

    /**
     * Exception error codes
     * @var array
     */
    protected static $exceptionCodes = array(
        0   =>  'invalid_request',
        1   =>  'unauthorized_client',
        2   =>  'access_denied',
        3   =>  'unsupported_response_type',
        4   =>  'invalid_scope',
        5   =>  'server_error',
        6   =>  'temporarily_unavailable',
        7   =>  'unsupported_grant_type',
        8   =>  'invalid_client',
        9   =>  'invalid_grant'
    );

    /**
     * Exception error messages
     * @var array
     */
    static protected $exceptionMessages = array(
        'invalid_request'           =>  'The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed. Check the "%s" parameter.',
        'unauthorized_client'       =>  'The client is not authorized to request an access token using this method.',
        'access_denied'             =>  'The resource owner or authorization server denied the request.',
        'unsupported_response_type' =>  'The authorization server does not support obtaining an access token using this method.',
        'invalid_scope'             =>  'The requested scope is invalid, unknown, or malformed. Check the "%s" scope.',
        'server_error'              =>  'The authorization server encountered an unexpected condition which prevented it from fulfilling the request.',
        'temporarily_unavailable'   =>  'The authorization server is currently unable to handle the request due to a temporary overloading or maintenance of the server.',
        'unsupported_grant_type'    =>  'The authorization grant type "%s" is not supported by the authorization server',
        'invalid_client'            =>  'Client authentication failed',
        'invalid_grant'             =>  'The provided authorization grant is invalid, expired, revoked, does not match the redirection URI used in the authorization request, or was issued to another client. Check the "%s" parameter.',
        'invalid_credentials'       =>  'The user credentials were incorrect.',
        'invalid_refresh'           =>  'The refresh token is invalid.',
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
     * Create a new OAuth2 authorization server
     *
     * @param ClientInterface  $client  A class which inherits from Storage/ClientInterface
     * @param SessionInterface $session A class which inherits from Storage/SessionInterface
     * @param ScopeInterface   $scope   A class which inherits from Storage/ScopeInterface
     */
    public function __construct(ClientInterface $client, SessionInterface $session, ScopeInterface $scope)
    {
        self::$storages = array(
            'client'    =>  $client,
            'session'   =>  $session,
            'scope' =>  $scope
        );
    }

    /**
     * Enable support for a grant
     * @param GrantTypeInterface $grantType  A grant class which conforms to Interface/GrantTypeInterface
     * @param null|string        $identifier An identifier for the grant (autodetected if not passed)
     */
    public function addGrantType(GrantTypeInterface $grantType, $identifier = null)
    {
        if (is_null($identifier)) {
            $identifier = $grantType->getIdentifier();
        }
        self::$grantTypes[$identifier] = $grantType;

        if ( ! is_null($grantType->getResponseType())) {
            $this->responseTypes[] = $grantType->getResponseType();
        }
    }

    /**
     * Check if a grant type has been enabled
     * @param  string  $identifier The grant type identifier
     * @return boolean             Returns "true" if enabled, "false" if not
     */
    public static function hasGrantType($identifier)
    {
        return (array_key_exists($identifier, self::$grantTypes));
    }

    /**
     * Require the "scope" paremter in checkAuthoriseParams()
     * @param  boolean $require
     * @return void
     */
    public function requireScopeParam($require = true)
    {
        $this->requireScopeParam = $require;
    }

    /**
     * Require the "state" paremter in checkAuthoriseParams()
     * @param  boolean $require
     * @return void
     */
    public function requireStateParam($require = false)
    {
        $this->requireStateParam = $require;
    }

    /**
     * Get the scope delimeter
     *
     * @return string The scope delimiter (default: ",")
     */
    public function getScopeDelimeter()
    {
        return $this->scopeDelimeter;
    }

    /**
     * Set the scope delimiter
     *
     * @param string $scopeDelimeter
     */
    public function setScopeDelimeter($scopeDelimeter)
    {
        $this->scopeDelimeter = $scopeDelimeter;
    }

    /**
     * Get the TTL for an access token
     * @return int The TTL
     */
    public static function getExpiresIn()
    {
        return self::$expiresIn;
    }

    /**
     * Set the TTL for an access token
     * @param int $expiresIn The new TTL
     */
    public function setExpiresIn($expiresIn)
    {
        self::$expiresIn = $expiresIn;
    }

    /**
     * Sets the Request Object
     *
     * @param Util\RequestInterface The Request Object
     */
    public function setRequest(Util\RequestInterface $request)
    {
        self::$request = $request;
    }

    /**
     * Gets the Request object.  It will create one from the globals if one is not set.
     *
     * @return Util\RequestInterface
     */
    public static function getRequest()
    {
        if (self::$request === null) {
            // @codeCoverageIgnoreStart
            self::$request = Request::buildFromGlobals();

        }
        // @codeCoverageIgnoreEnd

        return self::$request;
    }

    /**
     * Return a storage class
     * @param  string $obj The class required
     * @return Storage\ClientInterface|Storage\ScopeInterface|Storage\SessionInterface
     */
    public static function getStorage($obj)
    {
        return self::$storages[$obj];
    }

    /**
     * Check authorise parameters
     *
     * @param  array $inputParams Optional array of parsed $_GET keys
     * @throws \OAuth2\Exception\ClientException
     * @return array             Authorise request parameters
     */
    public function checkAuthoriseParams($inputParams = array())
    {
        // Auth params
        $authParams = self::getParam(array('client_id', 'redirect_uri', 'response_type', 'scope', 'state'), 'get', $inputParams);

        if (is_null($authParams['client_id'])) {
            throw new Exception\ClientException(sprintf(self::$exceptionMessages['invalid_request'], 'client_id'), 0);
        }

        if (is_null($authParams['redirect_uri'])) {
            throw new Exception\ClientException(sprintf(self::$exceptionMessages['invalid_request'], 'redirect_uri'), 0);
        }

        if ($this->requireStateParam === true && is_null($authParams['redirect_uri'])) {
            throw new Exception\ClientException(sprintf(self::$exceptionMessages['invalid_request'], 'redirect_uri'), 0);
        }

        // Validate client ID and redirect URI
        $clientDetails = self::getStorage('client')->getClient($authParams['client_id'], null, $authParams['redirect_uri']);

        if ($clientDetails === false) {
            throw new Exception\ClientException(self::$exceptionMessages['invalid_client'], 8);
        }

        $authParams['client_details'] = $clientDetails;

        if (is_null($authParams['response_type'])) {
            throw new Exception\ClientException(sprintf(self::$exceptionMessages['invalid_request'], 'response_type'), 0);
        }

        // Ensure response type is one that is recognised
        if ( ! in_array($authParams['response_type'], $this->responseTypes)) {
            throw new Exception\ClientException(self::$exceptionMessages['unsupported_response_type'], 3);
        }

        // Validate scopes
        $scopes = explode($this->scopeDelimeter, $authParams['scope']);

        for ($i = 0; $i < count($scopes); $i++) {
            $scopes[$i] = trim($scopes[$i]);
            if ($scopes[$i] === '') unset($scopes[$i]); // Remove any junk scopes
        }

        if ($this->requireScopeParam === true && count($scopes) === 0) {
            throw new Exception\ClientException(sprintf(self::$exceptionMessages['invalid_request'], 'scope'), 0);
        }

        $authParams['scopes'] = array();

        foreach ($scopes as $scope) {
            $scopeDetails = self::getStorage('scope')->getScope($scope);

            if ($scopeDetails === false) {
                throw new Exception\ClientException(sprintf(self::$exceptionMessages['invalid_scope'], $scope), 4);
            }

            $authParams['scopes'][] = $scopeDetails;
        }

        return $authParams;
    }

    /**
     * Parse a new authorise request
     *
     * @param  string $type        The session owner's type
     * @param  string $typeId      The session owner's ID
     * @param  array  $authParams  The authorise request $_GET parameters
     * @return string              An authorisation code
     */
    public function newAuthoriseRequest($type, $typeId, $authParams = array())
    {
        // Generate an auth code
        $authCode = SecureKey::make();

        // Remove any old sessions the user might have
        self::getStorage('session')->deleteSession($authParams['client_id'], $type, $typeId);

        // Create a new session
        $sessionId = self::getStorage('session')->createSession($authParams['client_id'], $authParams['redirect_uri'], $type, $typeId, $authCode);

        // Associate scopes with the new session
        foreach ($authParams['scopes'] as $scope)
        {
            self::getStorage('session')->associateScope($sessionId, $scope['id']);
        }

        return $authCode;
    }

    /**
     * Issue an access token
     *
     * @param  array $inputParams Optional array of parsed $_POST keys
     * @return array             Authorise request parameters
     */
    public function issueAccessToken($inputParams = array())
    {
        $grantType = self::getParam('grant_type', 'post', $inputParams);

        if (is_null($grantType)) {
            throw new Exception\ClientException(sprintf(self::$exceptionMessages['invalid_request'], 'grant_type'), 0);
        }

        // Ensure grant type is one that is recognised and is enabled
        if ( ! in_array($grantType, array_keys(self::$grantTypes))) {
            throw new Exception\ClientException(sprintf(self::$exceptionMessages['unsupported_grant_type'], $grantType), 7);
        }

        // Complete the flow
        return $this->getGrantType($grantType)->completeFlow($inputParams);
    }

    /**
     * Return a grant type class
     * @param  string $grantType The grant type identifer
     * @return class
     */
    protected function getGrantType($grantType)
    {
        return self::$grantTypes[$grantType];
    }

    /**
     * Get a parameter from passed input parameters or the Request class
     * @param  string|array $param Requried parameter
     * @param  string $method      Get/put/post/delete
     * @param  array  $inputParams Passed input parameters
     * @return mixed               'Null' if parameter is missing
     */
    public static function getParam($param = '', $method = 'get', $inputParams = array())
    {
        if (is_string($param)) {
            return (isset($inputParams[$param])) ? $inputParams[$param] : self::getRequest()->{$method}($param);
        } else {
            $response = array();
            foreach ($param as $p) {
                $response[$p] = self::getParam($p, $method, $inputParams);
            }
            return $response;
        }
    }

}
