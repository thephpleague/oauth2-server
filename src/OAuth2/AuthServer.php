<?php

namespace OAuth2;

use OAuth2\Util\SecureKey;
use OAuth2\Storage\SessionInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\Storage\ScopeInterface;
use OAuth2\Grant\GrantTypeInterface;

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

    static protected $expiresIn = 3600;

    protected $responseTypes = array();

    static protected $storages = array();

    static protected $grantTypes = array();

    static protected $request = null;

    /**
     * Exception error codes
     * @var array
     */
    protected $exceptionCodes = array(
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

    public static function getExceptionMessage($error = '')
    {
        return self::$exceptionMessages[$error];
    }

    public function __construct(ClientInterface $client, SessionInterface $session, ScopeInterface $scope)
    {
        self::$storages = array(
            'client'    =>  $client,
            'session'   =>  $session,
            'scope' =>  $scope
        );
    }

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

    public static function hasGrantType($identifier)
    {
        return (array_key_exists($identifier, self::$grantTypes));
    }

    public function getScopeDelimeter()
    {
        return $this->scopeDelimeter;
    }

    public function setScopeDelimeter($scope_delimeter)
    {
        $this->scopeDelimeter = $scope_delimeter;
    }

    public static function getExpiresIn()
    {
        return self::$expiresIn;
    }

    public function setExpiresIn($expiresIn)
    {
        $this->expiresIn = $expiresIn;
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
     * @return  RequestInterface
     */
    public static function getRequest()
    {
        if (self::$request === null) {
            self::$request = Request::buildFromGlobals();
        }

        return self::$request;
    }

    public static function getStorage($obj)
    {
        return self::$storages[$obj];
    }

    /**
     * Check authorise parameters
     *
     * @access public
     * @param  array $inputParams Optional array of parsed $_GET keys
     * @return array             Authorise request parameters
     */
    public function checkAuthoriseParams($inputParams = array())
    {
        $authParams = array();

        // Client ID
        $authParams['client_id'] = (isset($inputParams['client_id'])) ?
                                    $inputParams['client_id'] :
                                    self::getRequest()->get('client_id');

        if (is_null($authParams['client_id'])) {
            throw new Exception\ClientException(sprintf(self::$exceptionMessages['invalid_request'], 'client_id'), 0);
        }

        // Redirect URI
        $authParams['redirect_uri'] = (isset($inputParams['redirect_uri'])) ?
                                        $inputParams['redirect_uri'] :
                                        self::getRequest()->get('redirect_uri');

        if (is_null($authParams['redirect_uri'])) {
            throw new Exception\ClientException(sprintf(self::$exceptionMessages['invalid_request'], 'redirect_uri'), 0);
        }

        // Validate client ID and redirect URI
        $clientDetails = self::getStorage('client')->get($authParams['client_id'], null, $authParams['redirect_uri']);

        if ($clientDetails === false) {
            throw new Exception\ClientException(self::$exceptionMessages['invalid_client'], 8);
        }

        $authParams['client_details'] = $clientDetails;

        // Response type
       $authParams['response_type'] = (isset($inputParams['response_type'])) ?
                                        $inputParams['response_type'] :
                                        self::getRequest()->get('response_type');

        if (is_null($authParams['response_type'])) {
            throw new Exception\ClientException(sprintf(self::$exceptionMessages['invalid_request'], 'response_type'), 0);
        }

        // Ensure response type is one that is recognised
        if ( ! in_array($authParams['response_type'], $this->responseTypes)) {
            throw new Exception\ClientException(self::$exceptionMessages['unsupported_response_type'], 3);
        }

        // Get and validate scopes
        $scopes = (isset($inputParams['scope'])) ?
                        $inputParams['scope'] :
                        self::getRequest()->get('scope', '');

        $scopes = explode($this->scopeDelimeter, $scopes);

        for ($i = 0; $i < count($scopes); $i++) {
            $scopes[$i] = trim($scopes[$i]);
            if ($scopes[$i] === '') unset($scopes[$i]); // Remove any junk scopes
        }

        if (count($scopes) === 0) {
            throw new Exception\ClientException(sprintf(self::$exceptionMessages['invalid_request'], 'scope'), 0);
        }

        $authParams['scopes'] = array();

        foreach ($scopes as $scope) {
            $scopeDetails = self::getStorage('scope')->get($scope);

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
     * @param  string $type            The session owner's type
     * @param  string $typeId          The session owner's ID
     * @param  array  $authoriseParams The authorise request $_GET parameters
     * @return string                  An authorisation code
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
     * @access public
     * @param  array $inputParams Optional array of parsed $_POST keys
     * @return array             Authorise request parameters
     */
    public function issueAccessToken($inputParams = array())
    {
        $authParams['grant_type'] = (isset($inputParams['grant_type'])) ?
                                    $inputParams['grant_type'] :
                                    self::getRequest()->post('grant_type');

        if (is_null($authParams['grant_type'])) {
            throw new Exception\ClientException(sprintf(self::$exceptionMessages['invalid_request'], 'grant_type'), 0);
        }

        // Ensure grant type is one that is recognised and is enabled
        if ( ! in_array($authParams['grant_type'], array_keys(self::$grantTypes))) {
            throw new Exception\ClientException(sprintf(self::$exceptionMessages['unsupported_grant_type'], $authParams['grant_type']), 7);
        }

        // Complete the flow
        return $this->getCurrentGrantType($authParams['grant_type'])->completeFlow($inputParams, $authParams);
    }

    protected function getCurrentGrantType($grantType)
    {
        return self::$grantTypes[$grantType];
    }

}
