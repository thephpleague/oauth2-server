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
        // Get the required params
        $authParams = AuthServer::getParam(array('client_id', 'client_secret', 'refresh_token'), 'post', $inputParams);

        if (is_null($authParams['client_id'])) {
            throw new Exception\ClientException(sprintf(AuthServer::getExceptionMessage('invalid_request'), 'client_id'), 0);
        }

        if (is_null($authParams['client_secret'])) {
            throw new Exception\ClientException(sprintf(AuthServer::getExceptionMessage('invalid_request'), 'client_secret'), 0);
        }

        // Validate client ID and client secret
        $clientDetails = AuthServer::getStorage('client')->getClient($authParams['client_id'], $authParams['client_secret']);

        if ($clientDetails === false) {
            throw new Exception\ClientException(AuthServer::getExceptionMessage('invalid_client'), 8);
        }

        $authParams['client_details'] = $clientDetails;

        if (is_null($authParams['refresh_token'])) {
            throw new Exception\ClientException(sprintf(AuthServer::getExceptionMessage('invalid_request'), 'refresh_token'), 0);
        }

        // Validate refresh token
        $sessionId = AuthServer::getStorage('client')->validateRefreshToken(
            $authParams['refresh_token'],
            $authParams['client_id']
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