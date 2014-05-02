<?php

namespace LeagueTests\Entity;

use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Entity\AuthCodeEntity;
use League\OAuth2\Server\AuthorizationServer;
use \Mockery as M;

class AuthCodeTest extends \PHPUnit_Framework_TestCase
{
    function testSetGet()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');

        $session = M::mock('League\OAuth2\Server\Entity\SessionEntity');

        $code = new AuthCodeEntity($server);
        $code->setRedirectUri('http://foo/bar');
        $code->setToken('foobar');
        $code->setSession($session);

        $this->assertEquals('http://foo/bar', $code->getRedirectUri());
        $this->assertEquals('http://foo/bar?code=foobar', $code->generateRedirectUri());
        $this->assertTrue($code->getSession() instanceof \League\OAuth2\Server\Entity\SessionEntity);
    }

    function testSave()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $server->shouldReceive('setAuthCodeStorage');
        $server->shouldReceive('setSessionStorage');

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('create');
        $authCodeStorage->shouldReceive('associateScope');
        $authCodeStorage->shouldReceive('setServer');
        $authCodeStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->setId('foo')
        ]);

        $server->shouldReceive('getStorage')->with('auth_code')->andReturn($authCodeStorage);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getByAuthCode')->andReturn(
            (new SessionEntity($server))
        );
        $sessionStorage->shouldReceive('setServer');

        $server->shouldReceive('getStorage')->with('session')->andReturn($sessionStorage);

        $server->setAuthCodeStorage($authCodeStorage);
        $server->setSessionStorage($sessionStorage);

        $entity = new AuthCodeEntity($server);
        $this->assertTrue($entity->save() instanceof AuthCodeEntity);
    }

    function testExpire()
    {
        $server = new AuthorizationServer();

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('delete');
        $authCodeStorage->shouldReceive('setServer');

        $server->setAuthCodeStorage($authCodeStorage);

        $entity = new AuthCodeEntity($server);
        $this->assertSame($entity->expire(), null);
    }
}
