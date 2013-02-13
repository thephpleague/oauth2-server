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
        $authParams = AuthServer::getParam(array('client_id', 'client_secret', 'username', 'password'), 'post', $inputParams);

        if (is_null($authParams['client_id'])) {
            throw new Exception\ClientException(sprintf(AuthServer::getExceptionMessage('invalid_request'), 'client_id'), 0);
        }

        if (is_null($authParams['client_secret'])) {
            throw new Exception\ClientException(sprintf(AuthServer::getExceptionMessage('invalid_request'), 'client_secret'), 0);
        }

        // Validate client ID and redirect URI
        $clientDetails = AuthServer::getStorage('client')->getClient($authParams['client_id'], $authParams['client_secret']);

        if ($clientDetails === false) {
            throw new Exception\ClientException(AuthServer::getExceptionMessage('invalid_client'), 8);
        }

        $authParams['client_details'] = $clientDetails;

        if (is_null($authParams['username'])) {
            throw new Exception\ClientException(sprintf(AuthServer::getExceptionMessage('invalid_request'), 'username'), 0);
        }

        if (is_null($authParams['password'])) {
            throw new Exception\ClientException(sprintf(AuthServer::getExceptionMessage('invalid_request'), 'password'), 0);
        }

        // Check if user's username and password are correct
        $userId = call_user_func($this->getVerifyCredentialsCallback(), $authParams['username'], $authParams['password']);

        if ($userId === false) {
            throw new Exception\ClientException(AuthServer::getExceptionMessage('invalid_credentials'), 0);
        }

        // Generate an access token
        $accessToken = SecureKey::make();
        $refreshToken = (AuthServer::hasGrantType('refresh_token')) ? SecureKey::make() : null;

        $accessTokenExpires = time() + AuthServer::getExpiresIn();
        $accessTokenExpiresIn = AuthServer::getExpiresIn();

        // Delete any existing sessions just to be sure
        AuthServer::getStorage('session')->deleteSession($authParams['client_id'], 'user', $userId);

        // Create a new session
        AuthServer::getStorage('session')->createSession(
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

        $response = array(
            'access_token'  =>  $accessToken,
            'token_type'    =>  'bearer',
            'expires'       =>  $accessTokenExpires,
            'expires_in'    =>  $accessTokenExpiresIn
        );

        if (AuthServer::hasGrantType('refresh_token')) {
            $response['refresh_token'] = $refreshToken;
        }

        return $response;
    }

}