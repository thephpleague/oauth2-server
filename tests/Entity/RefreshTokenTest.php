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
        $entity = new RefreshToken($server);
        $entity->setAccessToken((new AccessToken($server)));

        $reflector = new \ReflectionClass($entity);
        $accessTokenProperty = $reflector->getProperty('accessToken');
        $accessTokenProperty->setAccessible(true);

        $this->assertTrue($accessTokenProperty->getValue($entity) instanceof AccessToken);
    }

    function testSave()
    {
        $server = new Authorization();

        $refreshTokenStorage = M::mock('League\OAuth2\Server\Storage\RefreshTokenInterface');
        $refreshTokenStorage->shouldReceive('create');
        $refreshTokenStorage->shouldReceive('setServer');
        $refreshTokenStorage->shouldReceive('associateScope');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('getByRefreshToken')->andReturn(
            (new AccessToken($server))->setToken('foobar')
        );
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new Scope($server))->setId('foo')
        ]);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getByAccessToken')->andReturn(
            (new Session($server))
        );
        $sessionStorage->shouldReceive('setServer');

        $server->setAccessTokenStorage($accessTokenStorage);
        $server->setRefreshTokenStorage($refreshTokenStorage);

        $entity = new RefreshToken($server);
        $this->assertSame(null, $entity->save());
    }

    function testExpire()
    {
        $server = new Authorization();

        $refreshTokenStorage = M::mock('League\OAuth2\Server\Storage\RefreshTokenInterface');
        $refreshTokenStorage->shouldReceive('delete');
        $refreshTokenStorage->shouldReceive('setServer');

        $server->setRefreshTokenStorage($refreshTokenStorage);

        $entity = new RefreshToken($server);
        $this->assertSame($entity->expire(), null);
    }
}
