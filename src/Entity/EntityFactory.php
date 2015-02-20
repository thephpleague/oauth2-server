<?php

namespace League\OAuth2\Server\Entity;

use League\OAuth2\Server\AbstractServer;

class EntityFactory implements EntityFactoryInterface
{
    public function __construct(AbstractServer $server)
    {
        $this->server = $server;
    }

    /**
     * @return AccessTokenEntityInterface
     */
    public function createAccessTokenEntity()
    {
        return new AccessTokenEntity($this->server);
    }

    /**
     * @return AuthCodeEntityInterface
     */
    public function createAuthCodeEntity()
    {
        return new AuthCodeEntity($this->server);
    }

    /**
     * @return RefreshTokenEntityInterface
     */
    public function createRefreshTokenEntity()
    {
        return new RefreshTokenEntity($this->server);
    }

    /**
     * @return SessionEntityInterface
     */
    public function createSessionEntity()
    {
        return new SessionEntity($this->server);
    }

}
