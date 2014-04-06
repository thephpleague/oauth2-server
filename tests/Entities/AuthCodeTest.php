<?php

namespace LeagueTests\Entities;

use League\OAuth2\Server\Entity\Scope;
use League\OAuth2\Server\Entity\Session;
use League\OAuth2\Server\Entity\AuthCode;
use League\OAuth2\Server\AuthorizationServer;
use \Mockery as M;

class AuthCodeTest extends \PHPUnit_Framework_TestCase
{
    function testSetGet()
    {
        $server = new AuthorizationServer;
        $session = M::mock('League\OAuth2\Server\Entity\Session');

        $code = new AuthCode($server);
        $code->setRedirectUri('http://foo/bar');
        $code->setToken('foobar');
        $code->setSession($session);

        $this->assertEquals('http://foo/bar', $code->getRedirectUri());
        $this->assertEquals('http://foo/bar?code=foobar', $code->generateRedirectUri());
        $this->assertTrue($code->getSession() instanceof \League\OAuth2\Server\Entity\Session);
    }

    function testSave()
    {
        $server = new AuthorizationServer();

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('create');
        $authCodeStorage->shouldReceive('associateScope');
        $authCodeStorage->shouldReceive('setServer');
        $authCodeStorage->shouldReceive('getScopes')->andReturn([
            (new Scope($server))->setId('foo')
        ]);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getByAuthCode')->andReturn(
            (new Session($server))
        );
        $sessionStorage->shouldReceive('setServer');

        $server->setAuthCodeStorage($authCodeStorage);
        $server->setSessionStorage($sessionStorage);

        $entity = new AuthCode($server);
        $this->assertTrue($entity->save() instanceof AuthCode);
    }

    function testExpire()
    {
        $server = new AuthorizationServer();

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('delete');
        $authCodeStorage->shouldReceive('setServer');

        $server->setAuthCodeStorage($authCodeStorage);

        $entity = new AuthCode($server);
        $this->assertSame($entity->expire(), null);
    }
}
