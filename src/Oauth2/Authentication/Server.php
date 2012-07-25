<?php

namespace Oauth2\Authentication;

class OAuthServerClientException extends \Exception {}

class OAuthServerUserException extends \Exception {}

class OAuthServerException extends \Exception {}

class Server
{
    private $db = null;

    private $config = array(
        'scope_delimeter'       =>  ',',
        'access_token_ttl'   =>  null
    );

    /**
     * Supported response types
     * @var array
     */
    private $response_types =   array(
        'code'
    );
    
    /**
     * Supported grant types
     * @var array
     */
    private $grant_types    =   array(
        'authorization_code'
    );
    public $exceptionCodes = array(
        0   =>  'invalid_request',
        1   =>  'unauthorized_client',
        2   =>  'access_denied',
        3   =>  'unsupported_response_type',
        4   =>  'invalid_scope',
        5   =>  'server_error',
        6   =>  'temporarily_unavailable',
        7   =>  'unsupported_grant_type',
        8   =>  'invalid_client',
        9   =>  'invalid_grant'
    );

    protected $errors = array(
        'invalid_request'   =>  'The request is missing a required parameter,
 includes an invalid parameter value, includes a parameter more than
 once, or is otherwise malformed. Check the "%s" parameter.',
        'unauthorized_client'   =>  'The client is not authorized to request an 
access token using this method.',
        'access_denied' =>  'The resource owner or authorization server denied 
the request.',
        'unsupported_response_type' =>  'The authorization server does not 
support obtaining an access token using this method.',
        'invalid_scope' =>  'The requested scope is invalid, unknown, or 
            malformed. Check the "%s" scope.',
        'server_error'  =>  'The authorization server encountered an unexpected 
condition which prevented it from fulfilling the request.',
        'temporarily_unavailable'   =>  'The authorization server is currently 
unable to handle the request due to a temporary overloading or 
maintenance of the server.',
        'unsupported_grant_type'    =>  'The authorization grant type is not
         supported by the authorization server',
        'invalid_client'    =>  'Client authentication failed',
        'invalid_grant'     =>  'The provided authorization grant is invalid,
         expired, revoked, does not match the redirection URI used in the
          authorization request, or was issued to another client. Check the
           "%s" parameter.'
    );

    /**
     * Constructor
     * 
     * @access public
     * @param  array $options Optional list of options to overwrite the defaults
     * @return void
     */
    public function __construct(array $options = null)
    {
        if ($options !== null) {
            $this->options = array_merge($this->config, $options);
        }
    }

    /**
     * Register a database abstrator class
     * 
     * @access public
     * @param  object $db A class that implements OAuth2ServerDatabase
     * @return void
     */
    public function registerDbAbstractor($db)
    {
        $this->db = $db;
    }

    /**
     * Check client authorise parameters
     * 
     * @access public
     * @param  array $authParams Optional array of parsed $_GET keys
     * @return array             Authorise request parameters
     */
    public function checkClientAuthoriseParams($authParams = null)
    {
        $params = array();

        // Client ID
        if ( ! isset($authParams['client_id']) && ! isset($_GET['client_id'])) {

            throw new OAuthServerClientException(sprintf(
                $this->errors['invalid_request'], 'client_id'), 0);

        } else {

            $params['client_id'] = (isset($authParams['client_id'])) ? 
                $authParams['client_id'] : $_GET['client_id'];

        }

        // Redirect URI
        if ( ! isset($authParams['redirect_uri']) && 
            ! isset($_GET['redirect_uri'])) {

            throw new OAuthServerClientException(sprintf(
                $this->errors['invalid_request'], 'redirect_uri'), 0);

        } else {

            $params['redirect_uri'] = (isset($authParams['redirect_uri'])) ? 
                $authParams['redirect_uri'] : $_GET['redirect_uri'];

        }

        // Validate client ID and redirect URI
        $clientDetails = $this->db->validateClient($params['client_id'], null, 
            $params['redirect_uri']);

        if ($clientDetails === false) {

            throw new OAuthServerClientException(
                $this->errors['invalid_client'], 8);
        }

        // Response type
        if ( ! isset($authParams['response_type']) && 
            ! isset($_GET['response_type'])) {

            throw new OAuthServerClientException(sprintf(
                $this->errors['invalid_request'], 'response_type'), 0);

        } else {

            $params['response_type'] = (isset($authParams['response_type'])) ? 
                $authParams['response_type'] : $_GET['response_type'];

            // Ensure response type is one that is recognised
            if ( ! in_array($params['response_type'], 
                $this->config['response_types'])) {

                throw new OAuthServerClientException(
                    $this->errors['unsupported_response_type'], 3);

            }
        }

        // Get and validate scopes
        if (isset($authParams['scope']) || isset($_GET['scope'])) {

            $scopes = $_GET['scope'];
            if (isset($authParams['client_id'])) {
                $authParams['scope'];
            }

            $scopes = explode($this->config['scope_delimeter'], $scopes);

            // Remove any junk scopes
            for ($i = 0; $i < count($scopes); $i++) {
                $scopes[$i] = trim($scopes[$i]);

                if ($scopes[$i] === '') {
                    unset($scopes[$i]);
                }
            }

            if (count($scopes) === 0) {

                throw new OAuthServerClientException(sprintf(
                    $this->errors['invalid_request'], 'scope'), 0);
            }

            $params['scopes'] = array();

            foreach ($scopes as $scope) {

                $scopeDetails = $this->db->getScope($scope);

                if ($scopeDetails === false) {

                    throw new OAuthServerClientException(sprintf(
                        $this->errors['invalid_scope'], $scope), 4);

                }

                $params['scopes'][] = $scopeDetails;

            }
        }

        return $params;
    }

    /**
     * Parse a new authorise request
     * 
     * @param  string $type            The session owner's type
     * @param  string $typeId          The session owner's ID
     * @param  array  $authoriseParams The authorise request $_GET parameters
     * @return string                  An authorisation code
     */
    public function newAuthoriseRequest($type, $typeId, $authoriseParams)
    {
        // Remove any old sessions the user might have
        $this->db->deleteSession(
            $authoriseParams['client_id'],
            $type,
            $typeId
        );

        // Create the new auth code
        $authCode = $this->newAuthCode(
            $authoriseParams['client_id'], 
            'user',
            $typeId,
            $authoriseParams['redirect_uri'], 
            $authoriseParams['scopes']
        );

        return $authCode;
    }

    /**
     * Generate a unique code
     * 
     * Generate a unique code for an authorisation code, or token
     * 
     * @return string A unique code
     */
    private function generateCode()
    {
        return sha1(uniqid(microtime()));
    }

    /**
     * Create a new authorisation code
     * 
     * @param  string $clientId    The client ID
     * @param  string $type        The type of the owner of the session
     * @param  string $typeId      The session owner's ID
     * @param  string $redirectUri The redirect URI
     * @param  array  $scopes      The requested scopes
     * @param  string $accessToken The access token (default = null)
     * @return string              An authorisation code
     */
    private function newAuthCode(
        $clientId,
        $type = 'user',
        $typeId,
        $redirectUri,
        $scopes = array(),
        $accessToken = null
        )
    {
        $authCode = $this->generateCode();

        // If an access token exists then update the existing session with the 
        // new authorisation code otherwise create a new session
        if ($accessToken !== null) {

            $this->db->updateSession(
                $clientId,
                $type,
                $typeId,
                $authCode,
                $accessToken,
                'request'
            );
        
        } else {

            // Delete any existing sessions just to be sure
            $this->db->deleteSession($clientId, $type, $typeId);
               
            // Create a new session     
            $sessionId = $this->db->newSession(
                $clientId,
                $redirectUri,
                $type,
                $typeId,
                $authCode,
                null,
                null,
                'request'
            );
                        
            // Add the scopes
            foreach ($scopes as $key => $scope) {

                $this->db->addSessionScope($sessionId, $scope['scope']);

            }

        }
        
        return $authCode;
    }

    /**
     * Complete the authorisation code grant
     * 
     * @access public
     * @param  array $authParams Optional array of parsed $_POST keys
     * @return array             Authorise request parameters
     */
    public function completeAuthCodeGrant($authParams = null)
    {
        $params = array();

        // Client ID
        if ( ! isset($authParams['client_id']) &&
         ! isset($_POST['client_id'])) {

            throw new OAuthServerClientException(sprintf(
                $this->errors['invalid_request'], 'client_id'), 0);

        } else {

            $params['client_id'] = (isset($authParams['client_id'])) ? 
                $authParams['client_id'] : $_POST['client_id'];

        }

        // Client secret
        if ( ! isset($authParams['client_secret']) &&
         ! isset($_POST['client_secret'])) {

            throw new OAuthServerClientException(sprintf(
                $this->errors['invalid_request'], 'client_secret'), 0);

        } else {

            $params['client_secret'] = (isset($authParams['client_secret'])) ? 
                $authParams['client_secret'] : $_POST['client_secret'];

        }

        // Redirect URI
        if ( ! isset($authParams['redirect_uri']) && 
            ! isset($_POST['redirect_uri'])) {

            throw new OAuthServerClientException(sprintf(
                $this->errors['invalid_request'], 'redirect_uri'), 0);

        } else {

            $params['redirect_uri'] = (isset($authParams['redirect_uri'])) ? 
                $authParams['redirect_uri'] : $_POST['redirect_uri'];

        }

        // Validate client ID and redirect URI
        $clientDetails = $this->db->validateClient($params['client_id'],
         $params['client_secret'], 
            $params['redirect_uri']);

        if ($clientDetails === false) {

            throw new OAuthServerClientException(
                $this->errors['invalid_client'], 8);
        }

        // Grant type (must be 'authorization_code')
        if ( ! isset($authParams['grant_type']) && 
            ! isset($_POST['grant_type'])) {

            throw new OAuthServerClientException(sprintf(
                $this->errors['invalid_request'], 'grant_type'), 0);

        } else {

            $params['grant_type'] = (isset($authParams['grant_type'])) ? 
                $authParams['grant_type'] : $_POST['grant_type'];

            // Ensure response type is one that is recognised
            if ($params['response_type'] !== 'authorization_code') {

                throw new OAuthServerClientException(
                    $this->errors['unsupported_grant_type'], 7);

            }
        }

        // The authorization code
        if ( ! isset($authParams['code']) && 
            ! isset($_GET['code'])) {

            throw new OAuthServerClientException(sprintf(
                $this->errors['invalid_request'], 'code'), 0);

        } else {

            $params['code'] = (isset($authParams['code'])) ? 
                $authParams['code'] : $_POST['code'];

        }

        // Verify the authorization code matches the client_id and the
        //  request_uri
        $sessionId = $this->db->validateAuthCode($params['client_id'],
         $params['request_uri'], $params['code']);

        if ( ! $sessionId) {

            throw new OAuthServerClientException(sprintf(
                $this->errors['invalid_grant'], 'code'), 9);
        
        } else {

            // A session ID was returned so update it with an access token,
            //  remove the authorisation code, change the stage to 'granted'

            $accessToken = $this->generateCode();

            $accessTokenExpires = ($this->config['access_token_ttl'] === null)
             ? null : time() + $this->config['access_token_ttl'];

            $this->db->updateSession($sessionId, null, $accessToken,
             $accessTokenExpires, 'granted');

            // Update the session's scopes to reference the access token
            $this->db->updateSessionScopeAccessToken($sessionId, $accessToken);

            return array(
                'access_token'  =>  $accessToken,
                'token_type'    =>  'bearer',
                'expires_in'    =>  $this->config['access_token_ttl']
            );
        }
    }

    /**
     * Generates the redirect uri with appended params
     * 
     * @param  string $redirectUri     The redirect URI
     * @param  array  $params          The parameters to be appended to the URL
     * @param  string $query_delimeter The query string delimiter (default: ?)
     * @return string                  The updated redirect URI
     */
    public function redirectUri($redirectUri, $params = array(), 
     $queryDelimeter = '?')
    {
      
        if (strstr($redirectUri, $queryDelimeter)) {

            $redirectUri = $redirectUri . '&' . http_build_query($params);

        } else {

            $redirectUri = $redirectUri . $queryDelimeter . 
            http_build_query($params);

        }
        
        return $redirectUri;

    }

}