<?php

namespace LeagueTests\Entities;

use League\OAuth2\Server\Entity\Scope;
use League\OAuth2\Server\Entity\Session;
use League\OAuth2\Server\Entity\AccessToken;
use League\OAuth2\Server\AuthorizationServer as Authorization;
use \Mockery as M;

class AccessTokenTests extends \PHPUnit_Framework_TestCase
{
    function testSave()
    {
        $server = new Authorization();

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('create');
        $accessTokenStorage->shouldReceive('associateScope');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new Scope($server))->setId('foo')
        ]);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getByAccessToken')->andReturn(
            (new Session($server))
        );
        $sessionStorage->shouldReceive('setServer');

        $server->setAccessTokenStorage($accessTokenStorage);
        $server->setSessionStorage($sessionStorage);

        $entity = new AccessToken($server);
        $this->assertTrue($entity->save() instanceof AccessToken);
    }

    function testExpire()
    {
        $server = new Authorization();

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('delete');
        $accessTokenStorage->shouldReceive('setServer');

        $server->setAccessTokenStorage($accessTokenStorage);

        $entity = new AccessToken($server);
        $this->assertSame($entity->expire(), null);
    }
}
