<?php
/**
 * OAuth 2.0 session interface
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entity;

/**
 * Session entity interface
 */
interface SessionInterface
{
    /**
     * Set the session identifier
     * @param  string $id
     * @return self
     */
    public function setId($id);

    /**
     * Return the session identifier
     * @return string
     */
    public function getId();

    /**
     * Associate a scope
     * @param  ScopeInterface $scope
     * @return self
     */
    public function associateScope(ScopeInterface $scope);

    /**
     * Check if access token has an associated scope
     * @param  string $scope Scope to check
     * @return bool
     */
    public function hasScope($scope);

    /**
     * Return all scopes associated with the session
     * @return ScopeEntity[]
     */
    public function getScopes();

    /**
     * Associate an access token with the session
     * @param  AccessTokenInterface $accessToken
     * @return self
     */
    public function associateAccessToken(AccessTokenInterface $accessToken);

    /**
     * Associate a refresh token with the session
     * @param  RefreshTokenInterface $refreshToken
     * @return self
     */
    public function associateRefreshToken(RefreshTokenInterface $refreshToken);

    /**
     * Associate a client with the session
     * @param  ClientEntity $client The client
     * @return self
     */
    public function associateClient(ClientInterface $client);

    /**
     * Return the session client
     * @return ClientEntity
     */
    public function getClient();

    /**
     * Set the session owner
     * @param  string $type The type of the owner (e.g. user, app)
     * @param  string $id   The identifier of the owner
     * @return self
     */
    public function setOwner($type, $id);

    /**
     * Return session owner identifier
     * @return string
     */
    public function getOwnerId();

    /**
     * Return session owner type
     * @return string
     */
    public function getOwnerType();

    /**
     * Save the session
     * @return void
     */
    public function save();
}
