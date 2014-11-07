<?php

namespace LeagueTests\Entity;

use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\RefreshTokenEntity;
use \Mockery as M;

class RefreshTokenEntityTest extends \PHPUnit_Framework_TestCase
{
    public function testSetAccessTokenId()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $entity = new RefreshTokenEntity($server);
        $entity->setAccessTokenId('foobar');

        $reflector = new \ReflectionClass($entity);
        $accessTokenProperty = $reflector->getProperty('accessTokenId');
        $accessTokenProperty->setAccessible(true);

        $this->assertSame($accessTokenProperty->getValue($entity), 'foobar');
    }

    public function testSetAccessToken()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $entity = new RefreshTokenEntity($server);
        $entity->setAccessToken((new AccessTokenEntity($server)));

        $reflector = new \ReflectionClass($entity);
        $accessTokenProperty = $reflector->getProperty('accessTokenEntity');
        $accessTokenProperty->setAccessible(true);

        $this->assertTrue($accessTokenProperty->getValue($entity) instanceof AccessTokenEntity);
    }

    public function testSave()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $server->shouldReceive('setAccessTokenStorage');
        $server->shouldReceive('setRefreshTokenStorage');

        $refreshTokenStorage = M::mock('League\OAuth2\Server\Storage\RefreshTokenInterface');
        $refreshTokenStorage->shouldReceive('create');
        $refreshTokenStorage->shouldReceive('setServer');
        $refreshTokenStorage->shouldReceive('associateScope');

        $server->shouldReceive('getRefreshTokenStorage')->andReturn($refreshTokenStorage);

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('get')->andReturn(
            (new AccessTokenEntity($server))->setId('foobar')
        );
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        ]);

        $server->shouldReceive('getAccessTokenStorage')->andReturn($accessTokenStorage);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getByAccessToken')->andReturn(
            (new SessionEntity($server))
        );
        $sessionStorage->shouldReceive('setServer');

        $server->shouldReceive('getSessionStorage')->andReturn($sessionStorage);

        $server->setAccessTokenStorage($accessTokenStorage);
        $server->setRefreshTokenStorage($refreshTokenStorage);

        $entity = new RefreshTokenEntity($server);
        $this->assertSame(null, $entity->save());
    }

    public function testExpire()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $server->shouldReceive('setRefreshTokenStorage');

        $refreshTokenStorage = M::mock('League\OAuth2\Server\Storage\RefreshTokenInterface');
        $refreshTokenStorage->shouldReceive('delete');
        $refreshTokenStorage->shouldReceive('setServer');

        $server->shouldReceive('getRefreshTokenStorage')->andReturn($refreshTokenStorage);

        $server->setRefreshTokenStorage($refreshTokenStorage);

        $entity = new RefreshTokenEntity($server);
        $this->assertSame($entity->expire(), null);
    }
}
