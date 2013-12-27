<?php
/**
 * OAuth 2.0 Password grant
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\ClientException;
use League\OAuth2\Server\Util\SecureKey;

/**
 * Password grant class
 *
 * This flow can be used to validate your own server
 */
class Password extends AbstractGrantType
{
    /**
     * Override constants
     */
    const GRANT_IDENTIFIER    = 'password';
    const GRANT_RESPONSE_TYPE = null;

    /**
     * Callback to authenticate a user's name and password
     *
     * @var callable
     */
    protected $credentialsCallback;

    /**
     * @param AuthorizationServer $authorizationServer
     * @param callable $callback
     */
    public function __construct(AuthorizationServer $authorizationServer, callable $callback)
    {
        parent::__construct($authorizationServer);
        $this->credentialsCallback = $callback;
    }

    /**
     * {@inheritDoc}
     */
    public function completeFlow($inputParams = null)
    {
        $request = $this->authorizationServer->getRequest();

        // Get the required params
        if (!$clientId = $request->query->get('client_id')) {
            throw new ClientException(
                sprintf(AuthorizationServer::getExceptionMessage('invalid_request'), 'client_id'), 0
            );
        }

        if (!$clientSecret = $request->query->get('client_secret')) {
            throw new ClientException(
                sprintf(AuthorizationServer::getExceptionMessage('invalid_request'), 'client_secret'), 0
            );
        }

        // Validate client ID and client secret
        $client = $this->authorizationServer->getStorage('client')->getClient(
            $clientId,
            $clientSecret,
            null,
            $this->getIdentifier()
        );

        if ($clientDetails === false) {
            throw new ClientException(AuthorizationServer::getExceptionMessage('invalid_client'), 8);
        }

        $client = new Client;
        $client->setId($clientDetails['id']);
        $client->setSecret($clientDetails['secret']);



        $username = $this->server->getRequest()->request->get('username', null);
        if (is_null($username)) {
            throw new ClientException(
                sprintf(Authorization::getExceptionMessage('invalid_request'), 'username'),
                0
            );
        }

        $password = $this->server->getRequest()->request->get('password', null);
        if (is_null($password)) {
            throw new ClientException(
                sprintf(Authorization::getExceptionMessage('invalid_request'), 'password'),
                0
            );
        }

        // Check if user's username and password are correct
        $userId = call_user_func($this->getVerifyCredentialsCallback(), $username, $password);

        if ($userId === false) {
            throw new Exception\ClientException($this->authServer->getExceptionMessage('invalid_credentials'), 0);
        }

        // Validate any scopes that are in the request
        $scopeParam = $this->server->getRequest()->request->get('scope', '');
        $scopes = $this->validateScopes($scopeParam);

        // Create a new session
        $session = new Session($this->server->getStorage('session'));
        $session->setOwner('user', $userId);
        $session->associateClient($client);

        // Generate an access token
        $accessToken = new AccessToken($this->server->getStorage('access_token'));
        $accessToken->setId(SecureKey::make());
        $accessToken->setTimestamp(time());
        $accessToken->setTTL($this->server->getAccessTokenTTL());

        // Associate scopes with the session and access token
        foreach ($scopes as $scope) {
            $accessToken->associateScope($scope);
            $session->associateScope($scope);
        }

        $response = [
            'access_token'  =>  $accessToken->getId(),
            'token_type'    =>  'Bearer',
            'expires'       =>  $accessToken->getExpireTime(),
            'expires_in'    =>  $accessToken->getTTL()
        ];

        // Associate a refresh token if set
        if ($this->server->hasGrantType('refresh_token')) {
            $refreshToken = new RefreshToken($this->server->getStorage('refresh_token'));
            $refreshToken->setId(SecureKey::make());
            $refreshToken->setTimestamp(time());
            $refreshToken->setTTL($this->server->getGrantType('refresh_token')->getRefreshTokenTTL());
            $response['refresh_token'] = $refreshToken->getId();
        }

        // Save everything
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
