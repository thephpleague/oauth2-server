<?php
/**
 * OAuth 2.0 Refresh token grant
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Grant;

use League\Event\Event;
use League\OAuth2\Server\Entity\AccessTokenInterface;
use League\OAuth2\Server\Entity\ClientInterface;
use League\OAuth2\Server\Entity\FactoryInterface;
use League\OAuth2\Server\Entity\RefreshTokenInterface;
use League\OAuth2\Server\Exception;
use League\OAuth2\Server\Util\SecureKey;
use League\OAuth2\Server\AuthorizationServer;

/**
 * Refresh token grant
 */
class RefreshTokenGrant extends AbstractGrant
{
    /**
     * {@inheritdoc}
     */
    protected $identifier = 'refresh_token';

    /**
     * Refresh token TTL (default = 604800 = 1 week)
     *
     * @var integer
     */
    protected $refreshTokenTTL = 604800;

    /**
     * @var FactoryInterface
     */
    private $entityFactory;

    /**
     * @param \League\OAuth2\Server\Entity\FactoryInterface $entityFactory
     */
    public function __construct(FactoryInterface $entityFactory)
    {
        $this->entityFactory = $entityFactory;
    }

	/**
     * {@inheritdoc}
     */
    public function setAuthorizationServer(AuthorizationServer $server)
    {
        parent::setAuthorizationServer($server);
		
		// Attach to the event emitter so that refresh tokens will automatically be created
		$RTClass = $this;
		$this->server->addEventListener('oauth.accesstoken.created', function(Event $event, AccessTokenInterface $accessToken, GrantTypeInterface $grant) use($RTClass) {
			$RTClass->accessTokenCreated($event, $accessToken, $grant);
		});
        return $this;
    }
	
    /**
     * When an access token is created also create a refresh token (as appropriate)
     * @param \League\Event\Event                               $event
     * @param \League\OAuth2\Server\Entity\AccessTokenInterface $accessToken
     * @param \League\OAuth2\Server\Grant\GrantTypeInterface    $grant
     */
    public function accessTokenCreated(Event $event, AccessTokenInterface $accessToken, GrantTypeInterface $grant)
    {
		// Refresh tokens are only supported for certain grant types
        if (in_array($grant->getIdentifier(), ['authorization_code', 'password']) === false) {
            return;
        }

        // Create and save the refresh token
        $refreshToken = $this->entityFactory->buildRefreshTokenEntity();
        $refreshToken->setId(SecureKey::generate());
        $refreshToken->setExpireTime($this->getRefreshTokenTTL() + time());
        $refreshToken->setAccessToken($accessToken);
        $refreshToken->save();

        // Set the refresh token on the token type
        $this->server->getTokenType()->setParam('refresh_token', $refreshToken->getId());
    }

    /**
     * Set the TTL of the refresh token
     *
     * @param int $refreshTokenTTL
     *
     * @return void
     */
    public function setRefreshTokenTTL($refreshTokenTTL)
    {
        $this->refreshTokenTTL = $refreshTokenTTL;
    }

    /**
     * Get the TTL of the refresh token
     *
     * @return int
     */
    public function getRefreshTokenTTL()
    {
        return $this->refreshTokenTTL;
    }

    /**
     * {@inheritdoc}
     */
    public function completeFlow()
    {
        $clientId = $this->server->getRequest()->request->get('client_id', $this->server->getRequest()->getUser());
        if (is_null($clientId)) {
            throw new Exception\InvalidRequestException('client_id');
        }

        $clientSecret = $this->server->getRequest()->request->get('client_secret',
            $this->server->getRequest()->getPassword());
        if (is_null($clientSecret)) {
            throw new Exception\InvalidRequestException('client_secret');
        }

        // Validate client ID and client secret
        $client = $this->server->getClientStorage()->get(
            $clientId,
            $clientSecret,
            null,
            $this->getIdentifier()
        );

        if (($client instanceof ClientInterface) === false) {
            $this->server->getEventEmitter()->emit('oauth.error.client.authfail', $this->server->getRequest());
            throw new Exception\InvalidClientException();
        }

        $oldRefreshTokenParam = $this->server->getRequest()->request->get('refresh_token', null);
        if ($oldRefreshTokenParam === null) {
            throw new Exception\InvalidRequestException('refresh_token');
        }

        // Validate refresh token
        $oldRefreshToken = $this->server->getRefreshTokenStorage()->get($oldRefreshTokenParam);

        if (($oldRefreshToken instanceof RefreshTokenInterface) === false) {
            throw new Exception\InvalidRefreshException();
        }

        // Ensure the old refresh token hasn't expired
        if ($oldRefreshToken->isExpired() === true) {
            throw new Exception\InvalidRefreshException();
        }

        $oldAccessToken = $oldRefreshToken->getAccessToken();

        // Get the scopes for the original session
        $session = $oldAccessToken->getSession();
        $scopes = $this->formatScopes($session->getScopes());

        // Get and validate any requested scopes
        $requestedScopesString = $this->server->getRequest()->request->get('scope', '');
        $requestedScopes = $this->validateScopes($requestedScopesString, $client);

        // If no new scopes are requested then give the access token the original session scopes
        if (count($requestedScopes) === 0) {
            $newScopes = $scopes;
        } else {
            // The OAuth spec says that a refreshed access token can have the original scopes or fewer so ensure
            //  the request doesn't include any new scopes
            foreach ($requestedScopes as $requestedScope) {
                if (!isset($scopes[$requestedScope->getId()])) {
                    throw new Exception\InvalidScopeException($requestedScope->getId());
                }
            }

            $newScopes = $requestedScopes;
        }

        // Generate a new access token and assign it the correct sessions
        $newAccessToken = $this->entityFactory->buildAccessTokenEntity();
        $newAccessToken->setId(SecureKey::generate());
        $newAccessToken->setExpireTime($this->getAccessTokenTTL() + time());
        $newAccessToken->setSession($session);

        foreach ($newScopes as $newScope) {
            $newAccessToken->associateScope($newScope);
        }

        // Expire the old token and save the new one
        $oldAccessToken->expire();
        $newAccessToken->save();

        $this->server->getTokenType()->setSession($session);
        $this->server->getTokenType()->setParam('access_token', $newAccessToken->getId());
        $this->server->getTokenType()->setParam('expires_in', $this->getAccessTokenTTL());

        // Expire the old refresh token
        $oldRefreshToken->expire();

        // Generate a new refresh token
        $newRefreshToken = $this->entityFactory->buildRefreshTokenEntity();
        $newRefreshToken->setId(SecureKey::generate());
        $newRefreshToken->setExpireTime($this->getRefreshTokenTTL() + time());
        $newRefreshToken->setAccessToken($newAccessToken);
        $newRefreshToken->save();

        $this->server->getEventEmitter()->emit('oauth.refreshtoken.created', $newRefreshToken);

        $this->server->getTokenType()->setParam('refresh_token', $newRefreshToken->getId());

        return $this->server->getTokenType()->generateResponse();
    }
}
