<?php
/**
 * OAuth 2.0 Password grant
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Authorization;
use League\OAuth2\Server\Entity\AccessToken;
use League\OAuth2\Server\Entity\Client;
use League\OAuth2\Server\Entity\RefreshToken;
use League\OAuth2\Server\Entity\Session;
use League\OAuth2\Server\Entity\Scope;
use League\OAuth2\Server\Exception\ClientException;
use League\OAuth2\Server\Exception\InvalidGrantTypeException;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\Storage\ClientInterface;
use League\OAuth2\Server\Storage\ScopeInterface;

/**
 * Password grant class
 */
class Password extends AbstractGrant
{
    /**
     * Grant identifier
     * @var string
     */
    protected $identifier = 'password';

    /**
     * Response type
     * @var string
     */
    protected $responseType;

    /**
     * Callback to authenticate a user's name and password
     * @var function
     */
    protected $callback;

    /**
     * Access token expires in override
     * @var int
     */
    protected $accessTokenTTL;

    /**
     * Set the callback to verify a user's username and password
     * @param callable $callback The callback function
     * @return void
     */
    public function setVerifyCredentialsCallback(callable $callback)
    {
        $this->callback = $callback;
    }

    /**
     * Return the callback function
     * @return callable
     */
    protected function getVerifyCredentialsCallback()
    {
        if (is_null($this->callback) || ! is_callable($this->callback)) {
            throw new InvalidGrantTypeException('Null or non-callable callback set on Password grant');
        }

        return $this->callback;
    }

    /**
     * Complete the password grant
     * @param  null|array $inputParams
     * @return array
     */
    public function completeFlow($inputParams = null)
    {
        // Get the required params
        $clientId = $this->server->getRequest()->request->get('client_id', null);
        if (is_null($clientId)) {
            throw new ClientException(
                sprintf(Authorization::getExceptionMessage('invalid_request'), 'client_id'),
                0
            );
        }

        $clientSecret = $this->server->getRequest()->request->get('client_secret', null);
        if (is_null($clientSecret)) {
            throw new ClientException(
                sprintf(Authorization::getExceptionMessage('invalid_request'), 'client_secret'),
                0
            );
        }

        // Validate client ID and client secret
        $client = $this->server->getStorage('client')->get(
            $clientId,
            $clientSecret,
            null,
            $this->getIdentifier()
        );

        if (($client instanceof Client) === false) {
            throw new ClientException(Authorization::getExceptionMessage('invalid_client'), 8);
        }

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
            throw new ClientException($this->server->getExceptionMessage('invalid_credentials'), 0);
        }

        // Validate any scopes that are in the request
        $scopeParam = $this->server->getRequest()->request->get('scope', '');
        $scopes = $this->validateScopes($scopeParam);

        // Create a new session
        $session = new Session($this->server);
        $session->setOwner('user', $userId);
        $session->associateClient($client);

        // Generate an access token
        $accessToken = new AccessToken($this->server);
        $accessToken->setToken(SecureKey::make());
        $accessToken->setExpireTime($this->server->getAccessTokenTTL() + time());

        // Associate scopes with the session and access token
        foreach ($scopes as $scope) {
            $accessToken->associateScope($scope);
            $session->associateScope($scope);
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
