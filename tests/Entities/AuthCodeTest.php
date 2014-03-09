<?php

namespace LeagueTests\Entities;

use League\OAuth2\Server\Entity\Scope;
use League\OAuth2\Server\Entity\Session;
use League\OAuth2\Server\Entity\AuthCode;
use League\OAuth2\Server\AuthorizationServer as Authorization;
use \Mockery as M;

class AuthCodeTest extends \PHPUnit_Framework_TestCase
{
    function testSave()
    {
        $server = new Authorization();

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
        $server = new Authorization();

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('delete');
        $authCodeStorage->shouldReceive('setServer');

        $server->setAuthCodeStorage($authCodeStorage);

        $entity = new AuthCode($server);
        $this->assertSame($entity->expire(), null);
    }
}
