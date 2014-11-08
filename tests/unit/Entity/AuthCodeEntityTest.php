<?php

namespace LeagueTests\Entity;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entity\AuthCodeEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use Mockery as M;

class AuthCodeEntityTest extends \PHPUnit_Framework_TestCase
{
    public function testSetGet()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');

        $session = M::mock('League\OAuth2\Server\Entity\SessionEntity');

        $code = new AuthCodeEntity($server);
        $code->setRedirectUri('http://foo/bar');
        $code->setId('foobar');
        $code->setSession($session);

        $this->assertEquals('http://foo/bar', $code->getRedirectUri());
        $this->assertEquals('http://foo/bar?code=foobar', $code->generateRedirectUri());
        $this->assertTrue($code->getSession() instanceof \League\OAuth2\Server\Entity\SessionEntity);
    }

    public function testSave()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $server->shouldReceive('setAuthCodeStorage');
        $server->shouldReceive('setSessionStorage');

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('create');
        $authCodeStorage->shouldReceive('associateScope');
        $authCodeStorage->shouldReceive('setServer');
        $authCodeStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo']),
        ]);

        $server->shouldReceive('getAuthCodeStorage')->andReturn($authCodeStorage);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getByAuthCode')->andReturn(
            (new SessionEntity($server))
        );
        $sessionStorage->shouldReceive('setServer');

        $server->shouldReceive('getSessionStorage')->andReturn($sessionStorage);

        $server->setAuthCodeStorage($authCodeStorage);
        $server->setSessionStorage($sessionStorage);

        $entity = new AuthCodeEntity($server);
        $this->assertTrue($entity->save() instanceof AuthCodeEntity);
    }

    public function testExpire()
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
