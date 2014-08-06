<?php
/**
 * OAuth 2.0 Refresh token entity
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */

namespace League\OAuth2\Server\Entity;

/**
 * Refresh token entity class
 */
class RefreshTokenEntity extends AbstractTokenEntity
{
    /**
     * Access token associated to refresh token
     * @var \League\OAuth2\Server\Entity\AccessTokenEntity
     */
    protected $accessTokenEntity;

    /**
     * Id of the access token
     * @var string
     */
    protected $accessTokenId;

    /**
     * Set the ID of the associated access token
     * @param  string $accessToken
     * @return self
     */
    public function setAccessTokenId($accessTokenId)
    {
        $this->accessTokenId = $accessTokenId;

        return $this;
    }

    /**
     * Associate an access token
     * @param  \League\OAuth2\Server\Entity\AccessTokenEntity $accessToken
     * @return self
     */
    public function setAccessToken(AccessTokenEntity $accessTokenEntity)
    {
        $this->accessTokenEntity = $accessTokenEntity;

        return $this;
    }

    /**
     * Return access token
     * @return AccessToken
     */
    public function getAccessToken()
    {
        if (! $this->accessTokenEntity instanceof AccessTokenEntity) {
            $this->accessTokenEntity = $this->server->getStorage('access_token')->get($this->accessTokenId);
        }

        return $this->accessTokenEntity;
    }

    /**
     * {@inheritdoc}
     */
    public function save()
    {
        $this->server->getStorage('refresh_token')->create(
            $this->getId(),
            $this->getExpireTime(),
            $this->getAccessToken()->getId()
        );
    }

    /**
     * {@inheritdoc}
     */
    public function expire()
    {
        $this->server->getStorage('refresh_token')->delete($this);
    }
}
