<?php

namespace OAuth2;

use OAuth2\Exception;

class AuthCode implements GrantTypeInterface {

    protected $identifier = 'AuthCode';
    protected $responseType = 'code';

    public function getIdentifier()
    {
        return $this->identifier;
    }

    public function getResponseType()
    {
        return $this->responseType;
    }

    public function completeFlow()
    {
        /*
        // Client ID
        if ( ! isset($authParams['client_id']) && ! isset($_POST['client_id'])) {
            throw new ClientException(sprintf($this->errors['invalid_request'], 'client_id'), 0);
        }

        $params['client_id'] = (isset($authParams['client_id'])) ?
                                    $authParams['client_id'] :
                                    $_POST['client_id'];

        // Client secret
        if ( ! isset($authParams['client_secret']) && ! isset($_POST['client_secret'])) {
            throw new ClientException(sprintf($this->errors['invalid_request'], 'client_secret'), 0);
        }

        $params['client_secret'] = (isset($authParams['client_secret'])) ?
                                        $authParams['client_secret'] :
                                        $_POST['client_secret'];

        // Redirect URI
        if ( ! isset($authParams['redirect_uri']) && ! isset($_POST['redirect_uri'])) {
            throw new ClientException(sprintf($this->errors['invalid_request'], 'redirect_uri'), 0);
        }

        $params['redirect_uri'] = (isset($authParams['redirect_uri'])) ?
                                        $authParams['redirect_uri'] :
                                        $_POST['redirect_uri'];

        // Validate client ID and redirect URI
        $clientDetails = $this->_dbCall(
            'validateClient',
            $params['client_id'],
            $params['client_secret'],
            $params['redirect_uri']
        );

        if ($clientDetails === false) {
            throw new ClientException($this->errors['invalid_client'], 8);
        }

        // The authorization code
        if ( ! isset($authParams['code']) && ! isset($_POST['code'])) {
            throw new ClientException(sprintf($this->errors['invalid_request'], 'code'), 0);
        }

        $params['code'] = (isset($authParams['code'])) ?
                                    $authParams['code'] :
                                    $_POST['code'];

        // Verify the authorization code matches the client_id and the request_uri
        $session = $this->_dbCall(
            'validateAuthCode',
            $params['client_id'],
            $params['redirect_uri'],
            $params['code']
        );

        if ( ! $session) {
            throw new ClientException(sprintf($this->errors['invalid_grant'], 'code'), 9);
        }

        // A session ID was returned so update it with an access token,
        //  remove the authorisation code, change the stage to 'granted'

        $accessToken = $this->_generateCode();
        $refreshToken = ($this->_grantTypes['refresh_token']) ?
                            $this->_generateCode() :
                            null;

        $accessTokenExpires = time() + $this->_config['access_token_ttl'];
        $accessTokenExpiresIn = $this->_config['access_token_ttl'];

        $this->_dbCall(
            'updateSession',
            $session['id'],
            null,
            $accessToken,
            $refreshToken,
            $accessTokenExpires,
            'granted'
        );

        // Update the session's scopes to reference the access token
        $this->_dbCall(
            'updateSessionScopeAccessToken',
            $session['id'],
            $accessToken,
            $refreshToken
        );

        $response = array(
            'access_token'  =>  $accessToken,
            'token_type'    =>  'bearer',
            'expires'       =>  $accessTokenExpires,
            'expires_in'    =>  $accessTokenExpiresIn
        );

        if ($this->_grantTypes['refresh_token']) {
            $response['refresh_token'] = $refreshToken;
        }

        return $response;

        */
    }

}