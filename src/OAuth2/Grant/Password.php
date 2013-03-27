<?php
/**
 * OAuth 2.0 Password grant
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
 * Password grant class
 */
class Password implements GrantTypeInterface {

    /**
     * Grant identifier
     * @var string
     */
    protected $identifier = 'password';

    /**
     * Response type
     * @var string
     */
    protected $responseType = null;

    /**
     * Callback to authenticate a user's name and password
     * @var function
     */
    protected $callback = null;

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
     * Set the callback to verify a user's username and password
     * @param function $callback The callback function
     */
    public function setVerifyCredentialsCallback($callback)
    {
        $this->callback = $callback;
    }

    /**
     * Return the callback function
     * @return function
     */
    protected function getVerifyCredentialsCallback()
    {
        if (is_null($this->callback) || ! is_callable($this->callback)) {
            throw new Exception\InvalidGrantTypeException('Null or non-callable callback set');
        }

        return $this->callback;
    }

    /**
     * Complete the password grant
     * @param  null|array $inputParams
     * @return array
     */
    public function completeFlow($inputParams = null)
    {
        // Get the required params
        $authParams = $this->authServer->getParam(array('client_id', 'client_secret', 'username', 'password'), 'post', $inputParams);

        if (is_null($authParams['client_id'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'client_id'), 0);
        }

        if (is_null($authParams['client_secret'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'client_secret'), 0);
        }

        // Validate client ID and redirect URI
        $clientDetails = $this->authServer->getStorage('client')->getClient($authParams['client_id'], $authParams['client_secret'], null, $this->identifier);


        if ($clientDetails === false) {
            throw new Exception\ClientException($this->authServer->getExceptionMessage('invalid_client'), 8);
        }

        $authParams['client_details'] = $clientDetails;

        if (is_null($authParams['username'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'username'), 0);
        }

        if (is_null($authParams['password'])) {
            throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_request'), 'password'), 0);
        }

        // Check if user's username and password are correct
        $userId = call_user_func($this->getVerifyCredentialsCallback(), $authParams['username'], $authParams['password']);

        if ($userId === false) {
            throw new Exception\ClientException($this->authServer->getExceptionMessage('invalid_credentials'), 0);
        }

        // Validate any scopes that are in the request
        $scope = $this->authServer->getParam('scope', 'post', $inputParams, '');
        $scopes = explode($this->authServer->getScopeDelimeter(), $scope);

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
            $scopeDetails = $this->authServer->getStorage('scope')->getScope($scope);

            if ($scopeDetails === false) {
                throw new Exception\ClientException(sprintf($this->authServer->getExceptionMessage('invalid_scope'), $scope), 4);
            }

            $authParams['scopes'][] = $scopeDetails;
        }

        // Generate an access token
        $accessToken = SecureKey::make();
        $refreshToken = ($this->authServer->hasGrantType('refresh_token')) ? SecureKey::make() : null;

        $accessTokenExpires = time() + $this->authServer->getExpiresIn();
        $accessTokenExpiresIn = $this->authServer->getExpiresIn();

        // Delete any existing sessions just to be sure
        $this->authServer->getStorage('session')->deleteSession($authParams['client_id'], 'user', $userId);

        // Create a new session
        $sessionId = $this->authServer->getStorage('session')->createSession(
            $authParams['client_id'],
            null,
            'user',
            $userId,
            null,
            $accessToken,
            $refreshToken,
            $accessTokenExpires,
            'granted'
        );

        // Associate scopes with the new session
        foreach ($authParams['scopes'] as $scope)
        {
            $this->authServer->getStorage('session')->associateScope($sessionId, $scope['id']);
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