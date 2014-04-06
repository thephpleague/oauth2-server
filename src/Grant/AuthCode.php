<?php
/**
 * OAuth 2.0 Auth code grant
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Request;
use League\OAuth2\Server\Exception;
use League\OAuth2\Server\Entity\Client;
use League\OAuth2\Server\Entity\RefreshToken;
use League\OAuth2\Server\Entity\Session;
use League\OAuth2\Server\Entity\AccessToken;
use League\OAuth2\Server\Entity\Scope;
use League\OAuth2\Server\Entity\AuthCode as AC;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\Storage\ClientInterface;
use League\OAuth2\Server\Storage\ScopeInterface;
use League\OAuth2\Server\Exception\ClientException;

/**
 * Auth code grant class
 */
class AuthCode extends AbstractGrant
{
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
        // Get required params
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
    public function newAuthoriseRequest($type, $typeId, $authParams = [])
    {
        // Create a new session
        $session = new Session($this->server);
        $session->setOwner($type, $typeId);
        $session->associateClient($authParams['client']);
        $session->save();

        // Create a new auth code
        $authCode = new AC($this->server);
        $authCode->setToken(SecureKey::make());
        $authCode->setRedirectUri($authParams['redirect_uri']);

        foreach ($authParams['scopes'] as $scope) {
            $authCode->associateScope($scope);
        }

        $authCode->setSession($session);
        $authCode->save();

        return $authCode->generateRedirectUri($authParams['state']);
    }

    /**
     * Complete the auth code grant
     * @param  null|array $inputParams
     * @return array
     */
    public function completeFlow($inputParams = null)
    {
        // Get the required params
        $clientId = $this->server->getRequest()->request->get('client_id', null);
        if (is_null($clientId)) {
            throw new ClientException(
                sprintf(AuthorizationServer::getExceptionMessage('invalid_request'), 'client_id'),
                0
            );
        }

        $clientSecret = $this->server->getRequest()->request->get('client_secret', null);
        if (is_null($clientSecret)) {
            throw new ClientException(
                sprintf(AuthorizationServer::getExceptionMessage('invalid_request'), 'client_secret'),
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

        // Validate client ID and client secret
        $client = $this->server->getStorage('client')->get(
            $clientId,
            $clientSecret,
            $redirectUri,
            $this->getIdentifier()
        );

        if (($client instanceof Client) === false) {
            throw new ClientException(AuthorizationServer::getExceptionMessage('invalid_client'), 8);
        }

        // Validate the auth code
        $authCode = $this->server->getRequest()->request->get('code', null);
        if (is_null($authCode)) {
            throw new ClientException(
                sprintf(AuthorizationServer::getExceptionMessage('invalid_request'), 'code'),
                0
            );
        }

        $code = $this->server->getStorage('auth_code')->get($authCode);
        if (($code instanceof AC) === false) {
            throw new ClientException(
                sprintf(AuthorizationServer::getExceptionMessage('invalid_request'), 'code'),
                9
            );
        }

        // Check redirect URI presented matches redirect URI originally used in authorise request
        if ($code->getRedirectUri() !== $redirectUri) {
            throw new ClientException(
                sprintf(AuthorizationServer::getExceptionMessage('invalid_request'), 'redirect_uri'),
                9
            );
        }

        $session = $code->getSession();
        $authCodeScopes = $code->getScopes();

        // Generate the access token
        $accessToken = new AccessToken($this->server);
        $accessToken->setToken(SecureKey::make());
        $accessToken->setExpireTime($this->server->getAccessTokenTTL() + time());

        foreach ($authCodeScopes as $authCodeScope) {
            $session->associateScope($authCodeScope);
        }

        $response = [
            'access_token'  =>  $accessToken->getToken(),
            'token_type'    =>  'Bearer',
            'expires'       =>  $accessToken->getExpireTime(),
            'expires_in'    =>  $this->server->getAccessTokenTTL()
        ];

        // Associate a refresh token if set
        if ($this->server->hasGrantType('refresh_token')) {
            $refreshToken = new RefreshToken($this->server);
            $refreshToken->setToken(SecureKey::make());
            $refreshToken->setExpireTime($this->server->getGrantType('refresh_token')->getRefreshTokenTTL() + time());
            $response['refresh_token'] = $refreshToken->getToken();
        }

        // Expire the auth code
        $code->expire();

        // Save all the things
        $session->save();
        $accessToken->setSession($session);
        $accessToken->save();

        if ($this->server->hasGrantType('refresh_token')) {
            $refreshToken->setAccessToken($accessToken);
            $refreshToken->save();
        }

        return $response;
    }
}
