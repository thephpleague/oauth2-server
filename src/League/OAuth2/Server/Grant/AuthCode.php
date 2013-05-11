<?php
/**
 * OAuth 2.0 Auth code grant
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Request;
use League\OAuth2\Server\Authorization;
use League\OAuth2\Server\Exception;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\Storage\ClientInterface;
use League\OAuth2\Server\Storage\ScopeInterface;

/**
 * Auth code grant class
 */
class AuthCode implements GrantTypeInterface {

    /**
     * Grant identifier
     * @var string
     */
    protected $identifier = 'authorization_code';

    /**
     * Response type
     * @var string
     */
    protected $responseType = 'code';

    /**
     * AuthServer instance
     * @var AuthServer
     */
    protected $authServer = null;

    /**
     * Access token expires in override
     * @var int
     */
    protected $accessTokenTTL = null;

    /**
     * The TTL of the auth token
     * @var integer
     */
    protected $authTokenTTL = 600;

    /**
     * Constructor
     * @param Authorization $authServer Authorization server instance
     * @return void
     */
    public function __construct(Authorization $authServer)
    {
        $this->authServer = $authServer;
    }

    /**
     * Return the identifier
     * @return string
     */
    public function getIdentifier()
    {
        return $this->identifier;
    }

    /**
     * Return the response type
     * @return string
     */
    public function getResponseType()
    {
        return $this->responseType;
    }

    /**
     * Override the default access token expire time
     * @param int $accessTokenTTL
     * @return void
     */
    public function setAccessTokenTTL($accessTokenTTL)
    {
        $this->accessTokenTTL = $accessTokenTTL;
    }

    /**
     * Override the default access token expire time
     * @param int $authTokenTTL
     * @return void
     */
    public function setAuthTokenTTL($authTokenTTL)
    {
        $this->authTokenTTL = $authTokenTTL;
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
        $authParams = $this->authServer->getParam(array('client_id', 'redirect_uri', 'response_type', 'scope', 'state'), 'get', $inputParams);

        if (is_null($authParams['client_id'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'client_id'), 0);
        }

        if (is_null($authParams['redirect_uri'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'redirect_uri'), 0);
        }

        if ($this->authServer->stateParamRequired() === true && is_null($authParams['state'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'state'), 0);
        }

        // Validate client ID and redirect URI
        $clientDetails = $this->authServer->getStorage('client')->getClient($authParams['client_id'], null, $authParams['redirect_uri'], $this->identifier);

        if ($clientDetails === false) {
            throw new Exception\ClientException($this->authServer->getExceptionMessage('invalid_client'), 8);
        }

        $authParams['client_details'] = $clientDetails;

        if (is_null($authParams['response_type'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'response_type'), 0);
        }

        // Ensure response type is one that is recognised
        if ( ! in_array($authParams['response_type'], $this->authServer->getResponseTypes())) {
            throw new Exception\ClientException($this->authServer->getExceptionMessage('unsupported_response_type'), 3);
        }

        // Validate scopes
        $scopes = explode($this->authServer->getScopeDelimeter(), $authParams['scope']);

        for ($i = 0; $i < count($scopes); $i++) {
            $scopes[$i] = trim($scopes[$i]);
            if ($scopes[$i] === '') unset($scopes[$i]); // Remove any junk scopes
        }

        if ($this->authServer->scopeParamRequired() === true && $this->authServer->getDefaultScope() === null && count($scopes) === 0) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'scope'), 0);
        } elseif (count($scopes) === 0 && $this->authServer->getDefaultScope() !== null) {
            if (is_array($this->authServer->getDefaultScope())) {
                $scopes = $this->authServer->getDefaultScope();
            } else {
                $scopes = array($this->authServer->getDefaultScope());
            }
        }

        $authParams['scopes'] = array();

        foreach ($scopes as $scope) {
            $scopeDetails = $this->authServer->getStorage('scope')->getScope($scope, $authParams['client_id'], $this->identifier);

            if ($scopeDetails === false) {
                throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_scope'), $scope), 4);
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
        $this->authServer->getStorage('session')->deleteSession($authParams['client_id'], $type, $typeId);

        // Create a new session
        $sessionId = $this->authServer->getStorage('session')->createSession($authParams['client_id'], $type, $typeId);

        // Associate a redirect URI
        $this->authServer->getStorage('session')->associateRedirectUri($sessionId, $authParams['redirect_uri']);

        // Associate the auth code
        $authCodeId = $this->authServer->getStorage('session')->associateAuthCode($sessionId, $authCode, time() + $this->authTokenTTL);

        // Associate the scopes to the auth code
        foreach ($authParams['scopes'] as $scope) {
            $this->authServer->getStorage('session')->associateAuthCodeScope($authCodeId, $scope['id']);
        }

        return $authCode;
    }

    /**
     * Complete the auth code grant
     * @param  null|array $inputParams
     * @return array
     */
    public function completeFlow($inputParams = null)
    {
        // Get the required params
        $authParams = $this->authServer->getParam(array('client_id', 'client_secret', 'redirect_uri', 'code'), 'post', $inputParams);

        if (is_null($authParams['client_id'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'client_id'), 0);
        }

        if (is_null($authParams['client_secret'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'client_secret'), 0);
        }

        if (is_null($authParams['redirect_uri'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'redirect_uri'), 0);
        }

        // Validate client ID and redirect URI
        $clientDetails = $this->authServer->getStorage('client')->getClient($authParams['client_id'], $authParams['client_secret'], $authParams['redirect_uri'], $this->identifier);

        if ($clientDetails === false) {
            throw new Exception\ClientException($this->authServer->getExceptionMessage('invalid_client'), 8);
        }

        $authParams['client_details'] = $clientDetails;

        // Validate the authorization code
        if (is_null($authParams['code'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'code'), 0);
        }

        // Verify the authorization code matches the client_id and the request_uri
        $authCodeDetails = $this->authServer->getStorage('session')->validateAuthCode($authParams['client_id'], $authParams['redirect_uri'], $authParams['code']);

        if ( ! $authCodeDetails) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_grant'), 'code'), 9);
        }

        // Get any associated scopes
        $scopes = $this->authServer->getStorage('session')->getAuthCodeScopes($authCodeDetails['authcode_id']);

        // A session ID was returned so update it with an access token and remove the authorisation code
        $accessToken = SecureKey::make();
        $accessTokenExpiresIn = ($this->accessTokenTTL !== null) ? $this->accessTokenTTL : $this->authServer->getAccessTokenTTL();
        $accessTokenExpires = time() + $accessTokenExpiresIn;

        // Remove the auth code
        $this->authServer->getStorage('session')->removeAuthCode($authCodeDetails['session_id']);

        // Create an access token
        $accessTokenId = $this->authServer->getStorage('session')->associateAccessToken($authCodeDetails['session_id'], $accessToken, $accessTokenExpires);

        // Associate scopes with the access token
        if (count($scopes) > 0) {
            foreach ($scopes as $scope) {
                $this->authServer->getStorage('session')->associateScope($accessTokenId, $scope['scope_id']);
            }
        }

        $response = array(
            'access_token'  =>  $accessToken,
            'token_type'    =>  'bearer',
            'expires'       =>  $accessTokenExpires,
            'expires_in'    =>  $accessTokenExpiresIn
        );

        // Associate a refresh token if set
        if ($this->authServer->hasGrantType('refresh_token')) {
            $refreshToken = SecureKey::make();
            $refreshTokenTTL = time() + $this->authServer->getGrantType('refresh_token')->getRefreshTokenTTL();
            $this->authServer->getStorage('session')->associateRefreshToken($accessTokenId, $refreshToken, $refreshTokenTTL, $authParams['client_id']);
            $response['refresh_token'] = $refreshToken;
        }

        return $response;
    }

}