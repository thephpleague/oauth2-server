<?php

namespace LNCD\OAuth2server;

class OAuthServerClientException extends Exception {}

class OAuthServerUserException extends Exception {}

class OAuthServerException extends Exception {}

class Server
{
    private $db = null;

    private $config = array(
        'response_types'    =>  array(
            'code'
        ),
        'scope_delimeter'   =>  ','
    );

    protected $errors = array(
        'invalid_request'   =>  'The request is missing a required parameter, 
            includes an invalid parameter value, includes a parameter more than 
            once, or is otherwise malformed.',
        'unauthorized_client'   =>  'The client is not authorized to request an 
            access token using this method.',
        'access_denied' =>  'The resource owner or authorization server denied 
            the request.',
        'unsupported_response_type' =>  'The authorization server does not 
            support obtaining an access token using this method.',
        'invalid_scope' =>  'The requested scope is invalid, unknown, or 
            malformed.',
        'server_error'  =>  'The authorization server encountered an unexpected 
            condition which prevented it from fulfilling the request.',
        'temporarily_unavailable'   =>  'The authorization server is currently 
        unable to handle the request due to a temporary overloading or 
        maintenance of the server.'
    ); 

    public function __construct(array $options = null)
    {
        if ($options !== null) {
            $this->options = array_merge($this->config, $options);
        }
    }

    public function registerDbAbstractor(object $db)
    {
        $this->db = $db;
    }

    public function checkAuthoriseParams(array $authParams = null)
    {
        $params = array();

        // Client ID
        if ( ! isset($authParams['client_id']) && ! isset($_GET['client_id'])) {

            throw new OAuthServerClientException('invalid_request: ' . 
                $this->errors['invalid_request']);

        } else {

            $params['client_id'] = (isset($authParams['client_id'])) ? 
                $authParams['client_id'] : $_GET['client_id'];

        }

        // Redirect URI
        if ( ! isset($authParams['redirect_uri']) && 
            ! isset($_GET['redirect_uri'])) {

            throw new OAuthServerClientException('invalid_request: ' . 
                $this->errors['invalid_request']);

        } else {

            $params['redirect_uri'] = (isset($authParams['redirect_uri'])) ? 
                $authParams['redirect_uri'] : $_GET['redirect_uri'];

        }

        // Validate client ID and redirect URI
        $clientDetails = $this->db->validateClient($params['client_id'], null, 
            $params['redirect_uri']);

        if ($clientDetails === false) {

            throw new OAuthServerClientException('unauthorized_client: ' . 
                $this->errors['unauthorized_client']);
        }

        // Response type
        if ( ! isset($authParams['response_type']) && 
            ! isset($_GET['response_type'])) {

            throw new OAuthServerClientException('invalid_request: ' . 
                $this->errors['invalid_request']);

        } else {

            $params['response_type'] = (isset($authParams['response_type'])) ? 
                $authParams['response_type'] : $_GET['response_type'];

            // Ensure response type is one that is recognised
            if ( ! in_array($params['response_type'], 
                $this->config['response_types'])) {

                throw new OAuthServerClientException('unsupported_response_type:
                 ' . $this->errors['unsupported_response_type']);

            }
        }

        // Get and validate scopes
        if (isset($authParams['scope']) || isset($_GET['scope'])) {

            $scopes = $_GET['scope'];
            if (isset($authParams['client_id'])) {
                $authParams['scope'];
            }

            $scopes = explode($this->config['scope_delimeter'], $scopes);

            for ($i = 0; $i++; $i < count($scopes)) {
                $scopes[$i] = trim($scopes[$i]);

                if ($scopes[$i] === '') {
                    unset($scopes[$i]);
                }
            }

            if (count($scopes) === 0) {

                throw new OAuthServerClientException('invalid_request: ' . 
                    $this->errors['invalid_request']);
            }

            $params['scopes'] = array();

            foreach ($scopes as $scope) {

                $scopeDetails = $this->db->getScope($scope);

                if ($scopeDetails === false) {

                    throw new OAuthServerClientException('invalid_scope: ' . 
                        $this->errors['invalid_scope']);

                }

                $params['scopes'][] = $scopeDetails;

            }
        }

        return $params;
    }

}