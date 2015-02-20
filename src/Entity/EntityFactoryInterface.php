<?php

namespace League\OAuth2\Server\Entity;

interface EntityFactoryInterface
{
    /**
     * @return AccessTokenEntityInterface
     */
    public function createAccessTokenEntity();

    /**
     * @return AuthCodeEntityInterface
     */
    public function createAuthCodeEntity();

    /**
     * @return RefreshTokenEntityInterface
     */
    public function createRefreshTokenEntity();

    /**
     * @return SessionEntityInterface
     */
    public function createSessionEntity();
}