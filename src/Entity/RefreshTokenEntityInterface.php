<?php

namespace League\OAuth2\Server\Entity;


/**
 * Refresh token entity class
 */
interface RefreshTokenEntityInterface extends AbstractTokenEntityInterface
{
    /**
     * Set the ID of the associated access token
     *
     * @param string $accessTokenId
     *
     * @return self
     */
    public function setAccessTokenId($accessTokenId);

    /**
     * Associate an access token
     *
     * @param \League\OAuth2\Server\Entity\AccessTokenEntity $accessTokenEntity
     *
     * @return self
     */
    public function setAccessToken(AccessTokenEntity $accessTokenEntity);

    /**
     * Return access token
     *
     * @return AccessTokenEntity
     */
    public function getAccessToken();

    /**
     * {@inheritdoc}
     */
    public function save();

    /**
     * {@inheritdoc}
     */
    public function expire();
}