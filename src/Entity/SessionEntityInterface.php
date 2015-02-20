<?php

namespace League\OAuth2\Server\Entity;


/**
 * Session entity grant
 */
interface SessionEntityInterface
{
    /**
     * Set the session identifier
     *
     * @param string $id
     *
     * @return self
     */
    public function setId($id);

    /**
     * Return the session identifier
     *
     * @return string
     */
    public function getId();

    /**
     * Associate a scope
     *
     * @param \League\OAuth2\Server\Entity\ScopeEntity $scope
     *
     * @return self
     */
    public function associateScope(ScopeEntity $scope);

    /**
     * Check if access token has an associated scope
     *
     * @param string $scope Scope to check
     *
     * @return bool
     */
    public function hasScope($scope);

    /**
     * Return all scopes associated with the session
     *
     * @return \League\OAuth2\Server\Entity\ScopeEntity[]
     */
    public function getScopes();

    /**
     * Associate an access token with the session
     *
     * @param \League\OAuth2\Server\Entity\AccessTokenEntity $accessToken
     *
     * @return self
     */
    public function associateAccessToken(AccessTokenEntity $accessToken);

    /**
     * Associate a refresh token with the session
     *
     * @param \League\OAuth2\Server\Entity\RefreshTokenEntity $refreshToken
     *
     * @return self
     */
    public function associateRefreshToken(RefreshTokenEntity $refreshToken);

    /**
     * Associate a client with the session
     *
     * @param \League\OAuth2\Server\Entity\ClientEntity $client The client
     *
     * @return self
     */
    public function associateClient(ClientEntity $client);

    /**
     * Return the session client
     *
     * @return \League\OAuth2\Server\Entity\ClientEntity
     */
    public function getClient();

    /**
     * Set the session owner
     *
     * @param string $type The type of the owner (e.g. user, app)
     * @param string $id The identifier of the owner
     *
     * @return self
     */
    public function setOwner($type, $id);

    /**
     * Return session owner identifier
     *
     * @return string
     */
    public function getOwnerId();

    /**
     * Return session owner type
     *
     * @return string
     */
    public function getOwnerType();

    /**
     * Save the session
     *
     * @return void
     */
    public function save();
}