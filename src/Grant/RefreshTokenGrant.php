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

use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\ClientEntity;
use League\OAuth2\Server\Entity\RefreshTokenEntity;
use League\OAuth2\Server\Event;
use League\OAuth2\Server\Exception;
use League\OAuth2\Server\Util\SecureKey;

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
     * Refresh token TTL (default = 604800 | 1 week)
     *
     * @var integer
     */
    protected $refreshTokenTTL = 604800;

    /**
     * Rotate token (default = true)
     *
     * @var integer
     */
    protected $refreshTokenRotate = true;

    /**
     * Whether to require the client secret when
     * completing the flow.
     *
     * @var boolean
     */
    protected $requireClientSecret = true;

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
     * Set the rotation boolean of the refresh token
     * @param bool $refreshTokenRotate
     */
    public function setRefreshTokenRotation($refreshTokenRotate = true)
    {
        $this->refreshTokenRotate = $refreshTokenRotate;
    }

    /**
     * Get rotation boolean of the refresh token
     *
     * @return bool
     */
    public function shouldRotateRefreshTokens()
    {
        return $this->refreshTokenRotate;
    }

    /**
     *
     * @param bool $required True to require client secret during access
     *                       token request. False if not. Default = true
     */
    public function setRequireClientSecret($required)
    {
        $this->requireClientSecret = $required;
    }

    /**
     * True if client secret is required during
     * access token request. False if it isn't.
     *
     * @return bool
     */
    public function shouldRequireClientSecret()
    {
        return $this->requireClientSecret;
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
        if ($this->shouldRequireClientSecret() && is_null($clientSecret)) {
            throw new Exception\InvalidRequestException('client_secret');
        }

        // Validate client ID and client secret
        $client = $this->server->getClientStorage()->get(
            $clientId,
            $clientSecret,
            null,
            $this->getIdentifier()
        );

        if (($client instanceof ClientEntity) === false) {
            $this->server->getEventEmitter()->emit(new Event\ClientAuthenticationFailedEvent($this->server->getRequest()));
            throw new Exception\InvalidClientException();
        }

        $oldRefreshTokenParam = $this->server->getRequest()->request->get('refresh_token', null);
        if ($oldRefreshTokenParam === null) {
            throw new Exception\InvalidRequestException('refresh_token');
        }

        // Validate refresh token
        $oldRefreshToken = $this->server->getRefreshTokenStorage()->get($oldRefreshTokenParam);

        if (($oldRefreshToken instanceof RefreshTokenEntity) === false) {
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
        $newAccessToken = new AccessTokenEntity($this->server);
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

        if ($this->shouldRotateRefreshTokens()) {
            // Expire the old refresh token
            $oldRefreshToken->expire();

            // Generate a new refresh token
            $newRefreshToken = new RefreshTokenEntity($this->server);
            $newRefreshToken->setId(SecureKey::generate());
            $newRefreshToken->setExpireTime($this->getRefreshTokenTTL() + time());
            $newRefreshToken->setAccessToken($newAccessToken);
            $newRefreshToken->save();

            $this->server->getTokenType()->setParam('refresh_token', $newRefreshToken->getId());
        } else {
            $this->server->getTokenType()->setParam('refresh_token', $oldRefreshToken->getId());
        }

        return $this->server->getTokenType()->generateResponse();
    }
}