<?php
/**
 * OAuth 2.0 Entity factory
 *
 * @package     league/oauth2-server
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 * @link        https://github.com/thephpleague/oauth2-server
 */
namespace League\OAuth2\Server\Entity;

use League\OAuth2\Server\AbstractServer;

/**
 * Entity factory
 */
class EntityFactory implements FactoryInterface
{
    /**
     * @var AbstractServer
     */
    private $server;

    public function __construct(AbstractServer $server)
    {
        $this->server = $server;
    }

    /**
     * @return accessTokenInterface
     */
    public function buildAccessTokenEntity()
    {
        return new AccessTokenEntity($this->server);
    }

    /**
     * @return authCodeInterface
     */
    public function buildAuthCodeEntity()
    {
        return new AuthCodeEntity($this->server);
    }

    /**
     * @return clientInterface
     */
    public function buildClientEntity()
    {
        return new ClientEntity($this->server);
    }

    /**
     * @return refreshTokenInterface
     */
    public function buildRefreshTokenEntity()
    {
        return new RefreshTokenEntity($this->server);
    }

    /**
     * @return scopeInterface
     */
    public function buildScopeEntity()
    {
        return new ScopeEntity($this->server);
    }

    /**
     * @return sessionInterface
     */
    public function buildSessionEntity()
    {
        return new SessionEntity($this->server);
    }
}
