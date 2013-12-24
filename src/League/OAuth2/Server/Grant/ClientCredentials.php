<?php
/**
 * OAuth 2.0 Client credentials grant
 *
 * @package     php-loep/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) 2013 PHP League of Extraordinary Packages
 * @license     http://mit-license.org/
 * @link        http://github.com/php-loep/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Authorization;
use League\OAuth2\Server\Entities\AccessToken;
use League\OAuth2\Server\Entities\Client;
use League\OAuth2\Server\Entities\Session;
use League\OAuth2\Server\Entities\Scope;
use League\OAuth2\Server\Exception\ClientException;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\Storage\SessionInterface;
use League\OAuth2\Server\Storage\ClientInterface;
use League\OAuth2\Server\Storage\ScopeInterface;

/**
 * Client credentials grant class
 */
class ClientCredentials implements GrantTypeInterface
{
    use GrantTrait;

    /**
     * Grant identifier
     * @var string
     */
    protected $identifier = 'client_credentials';

    /**
     * Response type
     * @var string
     */
    protected $responseType = null;

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
     * Complete the client credentials grant
     * @param  null|array $inputParams
     * @return array
     */
    public function completeFlow()
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
        $clientDetails = $this->server->getStorage('client')->getClient(
            $clientId,
            $clientSecret,
            null,
            $this->getIdentifier()
        );

        if ($clientDetails === false) {
            throw new ClientException(Authorization::getExceptionMessage('invalid_client'), 8);
        }

        $client = new Client;
        $client->setId($clientDetails['id']);
        $client->setSecret($clientDetails['secret']);

        // Validate any scopes that are in the request
        $scopeParam = $this->server->getRequest()->request->get('scope', '');
        $scopes = $this->validateScopes($scopeParam);

        // Create a new session
        $session = new Session($this->server->getStorage('session'));
        $session->setOwner('client', $client->getId());
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

        // Save everything
        $session->save();
        $accessToken->setSession($session);
        $accessToken->save();

        $response = [
            'access_token'  =>  $accessToken->getId(),
            'token_type'    =>  'Bearer',
            'expires'       =>  $accessToken->getExpireTime(),
            'expires_in'    =>  $accessToken->getTTL()
        ];

        return $response;
    }

}
