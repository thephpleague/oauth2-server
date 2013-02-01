<?php

namespace OAuth2\Grant;

use OAuth2\Request;
use OAuth2\AuthServer;
use OAuth2\Exception;
use OAuth2\Util\SecureKey;
use OAuth2\Storage\SessionInterface;
use OAuth2\Storage\ClientInterface;
use OAuth2\Storage\ScopeInterface;

class AuthCode implements GrantTypeInterface {

    protected $identifier = 'authorization_code';
    protected $responseType = 'code';

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

        // Redirect URI
        $authParams['redirect_uri'] = (isset($inputParams['redirect_uri'])) ?
                                        $inputParams['redirect_uri'] :
                                        AuthServer::getRequest()->post('redirect_uri');

        if (is_null($authParams['redirect_uri'])) {
            throw new Exception\ClientException(sprintf(AuthServer::getExceptionMessage('invalid_request'), 'redirect_uri'), 0);
        }

        // Validate client ID and redirect URI
        $clientDetails = AuthServer::getStorage('client')->get($authParams['client_id'], $authParams['client_secret'], $authParams['redirect_uri']);

        if ($clientDetails === false) {
            throw new Exception\ClientException(AuthServer::getExceptionMessage('invalid_client'), 8);
        }

        $authParams['client_details'] = $clientDetails;

        // The authorization code
        $authParams['code'] = (isset($inputParams['code'])) ?
                                $inputParams['code'] :
                                AuthServer::getRequest()->post('code');

        if (is_null($authParams['code'])) {
            throw new Exception\ClientException(sprintf(AuthServer::getExceptionMessage('invalid_request'), 'code'), 0);
        }

        // Verify the authorization code matches the client_id and the request_uri
        $session = AuthServer::getStorage('session')->validateAuthCode($authParams['client_id'], $authParams['redirect_uri'], $authParams['code']);

        if ( ! $session) {
            throw new Exception\ClientException(sprintf(AuthServer::getExceptionMessage('invalid_grant'), 'code'), 9);
        }

        // A session ID was returned so update it with an access token,
        //  remove the authorisation code, change the stage to 'granted'

        $accessToken = SecureKey::make();
        $refreshToken = (AuthServer::hasGrantType('refresh_token')) ? SecureKey::make() : null;

        $accessTokenExpires = time() + AuthServer::getExpiresIn();
        $accessTokenExpiresIn = AuthServer::getExpiresIn();

        AuthServer::getStorage('session')->update(
            $session['id'],
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