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
    protected $accessToken;

    /**
     * Associate an access token
     * @param  \League\OAuth2\Server\Entity\AccessTokenEntity $accessToken
     * @return self
     */
    public function setAccessToken(AccessTokenEntity $accessToken)
    {
        $this->accessToken = $accessToken;

        return $this;
    }

    /**
     * Return access token
     * @return AccessToken
     */
    public function getAccessToken()
    {
        if (! $this->accessToken instanceof AccessTokenEntity) {
            $this->accessToken = $this->server->getStorage('access_token')->getByRefreshToken($this);
        }

        return $this->accessToken;
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
