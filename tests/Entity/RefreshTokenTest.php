<?php

namespace LeagueTests\Entity;

use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\RefreshTokenEntity;
use League\OAuth2\Server\AuthorizationServer as Authorization;
use \Mockery as M;

class RefreshTokenTests extends \PHPUnit_Framework_TestCase
{
    function testSetAccessToken()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $entity = new RefreshTokenEntity($server);
        $entity->setAccessToken((new AccessTokenEntity($server)));

        $reflector = new \ReflectionClass($entity);
        $accessTokenProperty = $reflector->getProperty('accessToken');
        $accessTokenProperty->setAccessible(true);

        $this->assertTrue($accessTokenProperty->getValue($entity) instanceof AccessTokenEntity);
    }

    function testSave()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $server->shouldReceive('setAccessTokenStorage');
        $server->shouldReceive('setRefreshTokenStorage');

        $refreshTokenStorage = M::mock('League\OAuth2\Server\Storage\RefreshTokenInterface');
        $refreshTokenStorage->shouldReceive('create');
        $refreshTokenStorage->shouldReceive('setServer');
        $refreshTokenStorage->shouldReceive('associateScope');

        $server->shouldReceive('getStorage')->with('refresh_token')->andReturn($refreshTokenStorage);

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('getByRefreshToken')->andReturn(
            (new AccessTokenEntity($server))->setToken('foobar')
        );
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->setId('foo')
        ]);

        $server->shouldReceive('getStorage')->with('access_token')->andReturn($accessTokenStorage);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getByAccessToken')->andReturn(
            (new SessionEntity($server))
        );
        $sessionStorage->shouldReceive('setServer');

        $server->shouldReceive('getStorage')->with('session')->andReturn($sessionStorage);

        $server->setAccessTokenStorage($accessTokenStorage);
        $server->setRefreshTokenStorage($refreshTokenStorage);

        $entity = new RefreshTokenEntity($server);
        $this->assertSame(null, $entity->save());
    }

    function testExpire()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $server->shouldReceive('setRefreshTokenStorage');

        $refreshTokenStorage = M::mock('League\OAuth2\Server\Storage\RefreshTokenInterface');
        $refreshTokenStorage->shouldReceive('delete');
        $refreshTokenStorage->shouldReceive('setServer');

        $server->shouldReceive('getStorage')->with('refresh_token')->andReturn($refreshTokenStorage);

        $server->setRefreshTokenStorage($refreshTokenStorage);

        $entity = new RefreshTokenEntity($server);
        $this->assertSame($entity->expire(), null);
    }
}
