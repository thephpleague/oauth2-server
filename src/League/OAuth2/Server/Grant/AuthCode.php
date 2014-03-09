<?php
/**
 * OAuth 2.0 Auth code grant
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Request;
use League\OAuth2\Server\Authorization;
use League\OAuth2\Server\Exception;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\Storage\ClientInterface;
use League\OAuth2\Server\Storage\ScopeInterface;

/**
 * Auth code grant class
 */
class AuthCode implements GrantTypeInterface {

    use GrantTrait;

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
    protected $server = null;

    /**
     * Access token expires in override
     * @var int
     */
    protected $accessTokenTTL = null;

    /**
     * The TTL of the auth token
     * @var integer
     */
    protected $authTokenTTL = 600;

    /**
     * Override the default access token expire time
     * @param int $authTokenTTL
     * @return void
     */
    public function setAuthTokenTTL($authTokenTTL)
    {
        $this->authTokenTTL = $authTokenTTL;
    }

    /**
     * Check authorise parameters
     *
     * @throws
     * @return array Authorise request parameters
     */
    public function checkAuthoriseParams()
    {
        // Auth params
        $authParams = $this->server->getParam(array('client_id', 'redirect_uri', 'response_type', 'scope', 'state'), 'get', $inputParams);

        $clientId = $this->server->getRequest()->request->get('client_id', null);
        if (is_null($clientId)) {
            throw new ClientException(
                sprintf(AuthorizationServer::getExceptionMessage('invalid_request'), 'client_id'),
                0
            );
        }

        $redirectUri = $this->server->getRequest()->request->get('redirect_uri', null);
        if (is_null($redirectUri)) {
            throw new ClientException(
                sprintf(AuthorizationServer::getExceptionMessage('invalid_request'), 'redirect_uri'),
                0
            );
        }

        $state = $this->server->getRequest()->request->get('state', null);
        if ($this->server->stateParamRequired() === true && is_null($state)) {
            throw new ClientException(
                sprintf(AuthorizationServer::getExceptionMessage('invalid_request'), 'state'),
                0
            );
        }

        $responseType = $this->server->getRequest()->request->get('response_type', null);
        if (is_null($responseType)) {
            throw new ClientException(
                sprintf(AuthorizationServer::getExceptionMessage('invalid_request'), 'response_type'),
                0
            );
        }

        // Ensure response type is one that is recognised
        if ( ! in_array($responseType, $this->server->getResponseTypes())) {
            throw new ClientException(
                $this->server->getExceptionMessage('unsupported_response_type'),
                3
            );
        }

        // Validate client ID and redirect URI
        $client = $this->server->getStorage('client')->get(
            $clientId,
            null,
            $redirectUri,
            $this->getIdentifier()
        );

        if (($client instanceof Client) === false) {
            throw new ClientException(AuthorizationServer::getExceptionMessage('invalid_client'), 8);
        }

        // Validate any scopes that are in the request
        $scopeParam = $this->server->getRequest()->request->get('scope', '');
        $scopes = $this->validateScopes($scopeParam);

        return [
            'client'        =>  $client,
            'redirect_uri'  =>  $redirectUri,
            'state'         =>  $state,
            'response_type' =>  $responseType,
            'scopes'        =>  $scopes
        ];
    }

    /**
     * Parse a new authorise request
     *
     * @param  string $type        The session owner's type
     * @param  string $typeId      The session owner's ID
     * @param  array  $authParams  The authorise request $_GET parameters
     * @return string              An authorisation code
     */
    public function newAuthoriseRequest($type =, $typeId, $authParams = [])
    {
        // Generate an auth code
        $authCode = SecureKey::make();

        // Create a new session
        $session = new Session($this->server);
        $session->setOwner($type, $typeId);
        $session->associateClient($authParams['client']);

        // Associate a redirect URI
        $this->server->getStorage('session')->associateRedirectUri($sessionId, $authParams['redirect_uri']);

        // Associate the auth code
        $authCodeId = $this->server->getStorage('session')->associateAuthCode($sessionId, $authCode, time() + $this->authTokenTTL);

        // Associate the scopes to the auth code
        foreach ($authParams['scopes'] as $scope) {
            $this->server->getStorage('session')->associateAuthCodeScope($authCodeId, $scope['id']);
        }

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
        $authParams = $this->server->getParam(array('client_id', 'client_secret', 'redirect_uri', 'code'), 'post', $inputParams);

        if (is_null($authParams['client_id'])) {
            throw new Exception\ClientException(sprintf($this->server->getExceptionMessage('invalid_request'), 'client_id'), 0);
        }

        if (is_null($authParams['client_secret'])) {
            throw new Exception\ClientException(sprintf($this->server->getExceptionMessage('invalid_request'), 'client_secret'), 0);
        }

        if (is_null($authParams['redirect_uri'])) {
            throw new Exception\ClientException(sprintf($this->server->getExceptionMessage('invalid_request'), 'redirect_uri'), 0);
        }

        // Validate client ID and redirect URI
        $clientDetails = $this->server->getStorage('client')->getClient($authParams['client_id'], $authParams['client_secret'], $authParams['redirect_uri'], $this->identifier);

        if ($clientDetails === false) {
            throw new Exception\ClientException($this->server->getExceptionMessage('invalid_client'), 8);
        }

        $authParams['client_details'] = $clientDetails;

        // Validate the authorization code
        if (is_null($authParams['code'])) {
            throw new Exception\ClientException(sprintf($this->server->getExceptionMessage('invalid_request'), 'code'), 0);
        }

        // Verify the authorization code matches the client_id and the request_uri
        $authCodeDetails = $this->server->getStorage('session')->validateAuthCode($authParams['client_id'], $authParams['redirect_uri'], $authParams['code']);

        if ( ! $authCodeDetails) {
            throw new Exception\ClientException(sprintf($this->server->getExceptionMessage('invalid_grant'), 'code'), 9);
        }

        // Get any associated scopes
        $scopes = $this->server->getStorage('session')->getAuthCodeScopes($authCodeDetails['authcode_id']);

        // A session ID was returned so update it with an access token and remove the authorisation code
        $accessToken = SecureKey::make();
        $accessTokenExpiresIn = ($this->accessTokenTTL !== null) ? $this->accessTokenTTL : $this->server->getAccessTokenTTL();
        $accessTokenExpires = time() + $accessTokenExpiresIn;

        // Remove the auth code
        $this->server->getStorage('session')->removeAuthCode($authCodeDetails['session_id']);

        // Create an access token
        $accessTokenId = $this->server->getStorage('session')->associateAccessToken($authCodeDetails['session_id'], $accessToken, $accessTokenExpires);

        // Associate scopes with the access token
        if (count($scopes) > 0) {
            foreach ($scopes as $scope) {
                $this->server->getStorage('session')->associateScope($accessTokenId, $scope['scope_id']);
            }
        }

        $response = array(
            'access_token'  =>  $accessToken,
            'token_type'    =>  'Bearer',
            'expires'       =>  $accessTokenExpires,
            'expires_in'    =>  $accessTokenExpiresIn
        );

        // Associate a refresh token if set
        if ($this->server->hasGrantType('refresh_token')) {
            $refreshToken = SecureKey::make();
            $refreshTokenTTL = time() + $this->server->getGrantType('refresh_token')->getRefreshTokenTTL();
            $this->server->getStorage('session')->associateRefreshToken($accessTokenId, $refreshToken, $refreshTokenTTL, $authParams['client_id']);
            $response['refresh_token'] = $refreshToken;
        }

        return $response;
    }

}
