<?php

namespace OAuth2\Grant;

use OAuth2\Request;
use OAuth2\AuthServer;
use OAuth2\Exception;
use OAuth2\Util\SecureKey;
use OAuth2\Storage\SessionInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\Storage\ScopeInterface;

class RefreshToken implements GrantTypeInterface {

    protected $identifier = 'refresh_token';
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
        $clientDetails = AuthServer::getStorage('client')->get($authParams['client_id'], $authParams['client_secret']);

        if ($clientDetails === false) {
            throw new Exception\ClientException(AuthServer::getExceptionMessage('invalid_client'), 8);
        }

        $authParams['client_details'] = $clientDetails;

        // Refresh token
        $authParams['refresh_token'] = (isset($inputParams['refresh_token'])) ?
                                    $inputParams['refresh_token'] :
                                    AuthServer::getRequest()->post('refresh_token');

        if (is_null($authParams['refresh_token'])) {
            throw new Exception\ClientException(sprintf(AuthServer::getExceptionMessage('invalid_request'), 'refresh_token'), 0);
        }

        // Validate refresh token
        $sessionId = AuthServer::getStorage('client')->validateRefreshToken(
            $params['refresh_token'],
            $params['client_id']
        );

        if ($sessionId === false) {
            throw new Exception\ClientException(AuthServer::getExceptionMessage('invalid_refresh'), 0);
        }

        // Generate new tokens
        $accessToken = SecureKey::make();
        $refreshToken = (AuthServer::hasGrantType('refresh_token')) ? SecureKey::make() : null;

        $accessTokenExpires = time() + AuthServer::getExpiresIn();
        $accessTokenExpiresIn = AuthServer::getExpiresIn();

        AuthServer::getStorage('session')->updateRefreshToken($sessionId, $accessToken, $refreshToken, $accessTokenExpires);

        return array(
            'access_token'  =>  $accessToken,
            'refresh_token' =>  $refreshToken,
            'token_type'    =>  'bearer',
            'expires'       =>  $accessTokenExpires,
            'expires_in'    =>  $accessTokenExpiresIn
        );
    }

}