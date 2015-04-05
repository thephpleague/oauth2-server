<?php
namespace League\OAuth2\Server\Entities\Traits;

use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;

trait RefreshTokenTrait
{
    /**
     * @var AccessTokenEntityInterface
     */
    protected $originalAccessToken;

    /**
     * Set the original access token that the refresh token was associated with
     * @param \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface $accessToken
     */
    public function setOriginalAccessToken(AccessTokenEntityInterface $accessToken)
    {
        $this->originalAccessToken = $accessToken;
    }

    /**
     * Get the access token that the refresh token was originally associated with
     * @return \League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface
     */
    public function getOriginalAccessToken()
    {
        return $this->originalAccessToken;
    }
}