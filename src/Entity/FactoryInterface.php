<?php


namespace League\OAuth2\Server\Entity;


interface FactoryInterface
{
    /**
     * @return accessTokenInterface
     */
    public function buildAccessTokenEntity();

    /**
     * @return authCodeInterface
     */
    public function buildAuthCodeEntity();

    /**
     * @return clientInterface
     */
    public function buildClientEntity();

    /**
     * @return refreshTokenInterface
     */
    public function buildRefreshTokenEntity();

    /**
     * @return scopeInterface
     */
    public function buildScopeEntity();

    /**
     * @return sessionInterface
     */
    public function buildSessionEntity();
}