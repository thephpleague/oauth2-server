<?php

namespace LeagueTests\Entity;

use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use Mockery as M;

class AccessTokenEntityTest extends \PHPUnit_Framework_TestCase
{
    public function testSave()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $server->shouldReceive('setAccessTokenStorage');
        $server->shouldReceive('setSessionStorage');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('create');
        $accessTokenStorage->shouldReceive('associateScope');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->setId('foo'),
        ]);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getByAccessToken')->andReturn(
            (new SessionEntity($server))
        );
        $sessionStorage->shouldReceive('setServer');

        $server->shouldReceive('getSessionStorage')->andReturn($sessionStorage);
        $server->shouldReceive('getAccessTokenStorage')->andReturn($accessTokenStorage);

        $server->setAccessTokenStorage($accessTokenStorage);
        $server->setSessionStorage($sessionStorage);

        $entity = new AccessTokenEntity($server);
        $this->assertTrue($entity->save() instanceof AccessTokenEntity);
    }

    public function testExpire()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');

        $server->shouldReceive('setAccessTokenStorage');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('delete');
        $accessTokenStorage->shouldReceive('setServer');

        $server->shouldReceive('getAccessTokenStorage')->andReturn($accessTokenStorage);

        $server->setAccessTokenStorage($accessTokenStorage);

        $entity = new AccessTokenEntity($server);
        $this->assertSame($entity->expire(), null);
    }
}
