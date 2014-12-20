<?php
/**
 * OAuth 2.0 Implicit code grant
 *
 * @package     league/oauth2-server
 * @author      David Walker <dwalker@symplicity.com>
 * @copyright   Copyright (c) David Walker
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\ClientEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Event;
use League\OAuth2\Server\Exception;
use League\OAuth2\Server\Util\SecureKey;

/**
 * Implicit grant class
 */
class ImplicitGrant extends AbstractGrant
{
    /**
     * Grant identifier
     *
     * @var string
     */
    protected $identifier = 'implicit';

    /**
     * Response type
     *
     * @var string
     */
    protected $responseType = 'token';

    /**
     * AuthServer instance
     *
     * @var \League\OAuth2\Server\AuthorizationServer
     */
    protected $server = null;

    /**
     * Access token expires in override
     *
     * @var int
     */
    protected $accessTokenTTL = null;

    /**
     * Check authorize parameters
     *
     * @return array Authorize request parameters
     *
     * @throws
     */
    public function checkAuthorizeParams()
    {
        // Get required params
        $clientId = $this->server->getRequest()->query->get('client_id', null);
        if (is_null($clientId)) {
            throw new Exception\InvalidRequestException('client_id');
        }

        $redirectUri = $this->server->getRequest()->query->get('redirect_uri', null);
        if (is_null($redirectUri)) {
            throw new Exception\InvalidRequestException('redirect_uri');
        }

        // Validate client ID and redirect URI
        $client = $this->server->getClientStorage()->get(
            $clientId,
            null,
            $redirectUri,
            $this->getIdentifier()
        );

        if (($client instanceof ClientEntity) === false) {
            $this->server->getEventEmitter()->emit(new Event\ClientAuthenticationFailedEvent($this->server->getRequest()));
            throw new Exception\InvalidClientException();
        }

        $state = $this->server->getRequest()->query->get('state', null);
        if ($this->server->stateParamRequired() === true && is_null($state)) {
            throw new Exception\InvalidRequestException('state', $redirectUri);
        }

        $responseType = $this->server->getRequest()->query->get('response_type', null);
        if (is_null($responseType)) {
            throw new Exception\InvalidRequestException('response_type', $redirectUri);
        }

        // Ensure response type is one that is recognised
        if (!in_array($responseType, $this->server->getResponseTypes())) {
            throw new Exception\UnsupportedResponseTypeException($responseType, $redirectUri);
        }

        // Validate any scopes that are in the request
        $scopeParam = $this->server->getRequest()->query->get('scope', '');
        $scopes = $this->validateScopes($scopeParam, $client, $redirectUri);

        return [
            'client'        => $client,
            'redirect_uri'  => $redirectUri,
            'state'         => $state,
            'response_type' => $responseType,
            'scopes'        => $scopes
        ];
    }

    /**
     * Complete the flow. - invalid for this case
     *
     * @return null
     */
    public function completeFlow()
    {
    }

    /**
     * Generate the redirect URI for the Implicit grant
     *
     * @param array $params
     *
     * @return null
     */
    public function getRedirectUri($params)
    {
        // Get required params
        if (!isset($params['client']) || ($params['client'] instanceof ClientEntity) === false) {
            $this->server->getEventEmitter()->emit(new Event\ClientAuthenticationFailedEvent($this->server->getRequest()));
            throw new Exception\InvalidClientException();
        }
        $client = $params['client'];

        if (!isset($params['redirect_uri']) || is_null($params['redirect_uri'])) {
            throw new Exception\InvalidRequestException('redirect_uri');
        }
        $redirectUri = $params['redirect_uri'];

        // Create a new session
        $session = new SessionEntity($this->server);
        $session->setOwner('implicit', $client->getId());
        $session->associateClient($client);

        // Generate the access token
        $accessToken = new AccessTokenEntity($this->server);
        $accessToken->setId(SecureKey::generate());
        $accessToken->setExpireTime($this->getAccessTokenTTL() + time());

        if (isset($params['scopes'])) {
            foreach ($params['scopes'] as $implicitScope) {
                $session->associateScope($implicitScope);
            }

            foreach ($session->getScopes() as $scope) {
                $accessToken->associateScope($scope);
            }
        }

        $this->server->getTokenType()->setSession($session);
        $this->server->getTokenType()->setParam('access_token', $accessToken->getId());
        $this->server->getTokenType()->setParam('expires_in', $this->getAccessTokenTTL());

        // Save all the things
        $session->save();
        $accessToken->setSession($session);
        $accessToken->save();

        $token = $this->server->getTokenType()->generateResponse();
        if (isset($params['state']) && $params['state']) {
            $token['state'] = $params['state'];
        }

        return $params['redirect_uri'] . '#' . join('&', array_map(function($v, $k){return $k.'='.$v;}, $token, array_keys($token)));
    }
}
