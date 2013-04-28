<?php
/**
 * OAuth 2.0 Auth code grant
 *
 * @package     lncd/oauth2
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 University of Lincoln
 * @license     http://mit-license.org/
 * @link        http://github.com/lncd/oauth2
 */

namespace OAuth2\Grant;

use OAuth2\Request;
use OAuth2\AuthServer;
use OAuth2\Exception;
use OAuth2\Util\SecureKey;
use OAuth2\Storage\SessionInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\Storage\ScopeInterface;

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
     * Constructor
     * @param AuthServer $authServer AuthServer instance
     * @return void
     */
    public function __construct(AuthServer $authServer)
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
        $clientDetails = $this->authServer->getStorage('client')->getClient($authParams['client_id'], null, $authParams['redirect_uri']);

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

        if ($this->authServer->scopeParamRequired() === true && count($scopes) === 0) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'scope'), 0);
        } elseif (count($scopes) === 0 && $this->authServer->getDefaultScope()) {
            $scopes = array($this->authServer->getDefaultScope());
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

        // List of scopes IDs
        $scopeIds = array();
        foreach ($authParams['scopes'] as $scope)
        {
            $scopeIds[] = $scope['id'];
        }

        // Create a new session
        $sessionId = $this->authServer->getStorage('session')->createSession(array(
            'client_id' =>  $authParams['client_id'],
            'owner_type'  =>  $type,
            'owner_id'  =>  $typeId,
            'redirect_uri'  =>$authParams['redirect_uri'],
            'auth_code' =>  $authCode,
            'scope_ids' =>  implode(',', $scopeIds)
        ));

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
        $session = $this->authServer->getStorage('session')->validateAuthCode($authParams['client_id'], $authParams['redirect_uri'], $authParams['code']);

        if ( ! $session) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_grant'), 'code'), 9);
        }

        // A session ID was returned so update it with an access token and remove the authorisation code

        $accessToken = SecureKey::make();
        $refreshToken = ($this->authServer->hasGrantType('refresh_token')) ? SecureKey::make() : null;

        $accessTokenExpires = time() + $this->authServer->getExpiresIn();
        $accessTokenExpiresIn = $this->authServer->getExpiresIn();

        $this->authServer->getStorage('session')->deleteAuthCode($session['id']);

        $accessTokenId = $this->authServer->getStorage('session')->updateSession($session['id'], array(
            'access_token'  =>  $accessToken,
            'access_token_expire'  =>  $accessTokenExpires,
            'refresh_token'  =>  $refreshToken
        ));

        // Associate scopes with the access token
        if ( ! is_null($session['scope_ids'])) {
            $scopeIds = explode(',', $session['scope_ids']);

            foreach ($scopeIds as $scopeId) {
                $this->authServer->getStorage('session')->associateScope($accessTokenId, $scopeId);
            }
        }

        $response = array(
            'access_token'  =>  $accessToken,
            'token_type'    =>  'bearer',
            'expires'       =>  $accessTokenExpires,
            'expires_in'    =>  $accessTokenExpiresIn
        );

        if ($this->authServer->hasGrantType('refresh_token')) {
            $response['refresh_token'] = $refreshToken;
        }

        return $response;
    }

}