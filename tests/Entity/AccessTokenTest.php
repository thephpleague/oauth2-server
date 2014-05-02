<?php

namespace LeagueTests\Entity;

use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\AuthorizationServer;
use \Mockery as M;

class AccessTokenTests extends \PHPUnit_Framework_TestCase
{
    function testSave()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $server->shouldReceive('setAccessTokenStorage');
        $server->shouldReceive('setSessionStorage');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('create');
        $accessTokenStorage->shouldReceive('associateScope');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->setId('foo')
        ]);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getByAccessToken')->andReturn(
            (new SessionEntity($server))
        );
        $sessionStorage->shouldReceive('setServer');

        $server->shouldReceive('getStorage')->with('session')->andReturn($sessionStorage);
        $server->shouldReceive('getStorage')->with('access_token')->andReturn($accessTokenStorage);

        $server->setAccessTokenStorage($accessTokenStorage);
        $server->setSessionStorage($sessionStorage);

        $entity = new AccessTokenEntity($server);
        $this->assertTrue($entity->save() instanceof AccessTokenEntity);
    }

    function testExpire()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');

        $server->shouldReceive('setAccessTokenStorage');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('delete');
        $accessTokenStorage->shouldReceive('setServer');

        $server->shouldReceive('getStorage')->with('access_token')->andReturn($accessTokenStorage);

        $server->setAccessTokenStorage($accessTokenStorage);

        $entity = new AccessTokenEntity($server);
        $this->assertSame($entity->expire(), null);
    }
}
