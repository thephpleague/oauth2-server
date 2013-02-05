<?php

namespace OAuth2\Grant;

use OAuth2\Request;
use OAuth2\AuthServer;
use OAuth2\Exception;
use OAuth2\Util\SecureKey;
use OAuth2\Storage\SessionInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\Storage\ScopeInterface;

class ClientCredentials implements GrantTypeInterface {

    protected $identifier = 'client_credentials';
    protected $responseType = null;

    public function getIdentifier()
    {
        return $this->identifier;
    }

    public function getResponseType()
    {
        return $this->responseType;
    }

    public function completeFlow($inputParams = null, $authParams = array())
    {
        // Client ID
        $authParams['client_id'] = (isset($inputParams['client_id'])) ?
                                    $inputParams['client_id'] :
                                    AuthServer::getRequest()->post('client_id');

        if (is_null($authParams['client_id'])) {
            throw new Exception\ClientException(sprintf(AuthServer::getExceptionMessage('invalid_request'), 'client_id'), 0);
        }

        // Client secret
        $authParams['client_secret'] = (isset($inputParams['client_secret'])) ?
                                    $inputParams['client_secret'] :
                                    AuthServer::getRequest()->post('client_secret');

        if (is_null($authParams['client_secret'])) {
            throw new Exception\ClientException(sprintf(AuthServer::getExceptionMessage('invalid_request'), 'client_secret'), 0);
        }

        // Validate client ID and redirect URI
        $clientDetails = AuthServer::getStorage('client')->getClient($authParams['client_id'], $authParams['client_secret']);

        if ($clientDetails === false) {
            throw new Exception\ClientException(AuthServer::getExceptionMessage('invalid_client'), 8);
        }

        $authParams['client_details'] = $clientDetails;

        // Generate an access token
        $accessToken = SecureKey::make();
        $refreshToken = (AuthServer::hasGrantType('refresh_token')) ? SecureKey::make() : null;

        $accessTokenExpires = time() + AuthServer::getExpiresIn();
        $accessTokenExpiresIn = AuthServer::getExpiresIn();

        // Delete any existing sessions just to be sure
        AuthServer::getStorage('session')->deleteSession($authParams['client_id'], 'client', $authParams['client_id']);

        // Create a new session
        AuthServer::getStorage('session')->createSession(
            $authParams['client_id'],
            null,
            'client',
            $authParams['client_id'],
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