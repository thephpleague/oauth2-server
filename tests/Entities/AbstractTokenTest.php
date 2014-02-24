<?php

namespace LeagueTests\Entities;

use LeagueTests\Stubs\StubAbstractToken;
use League\OAuth2\Server\Entity\Session;
use League\OAuth2\Server\Entity\Scope;
use League\OAuth2\Server\AuthorizationServer as Authorization;
use \Mockery as M;

class AbstractTokenTests extends \PHPUnit_Framework_TestCase
{
    public function testSetGet()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $time = time();

        $entity = new StubAbstractToken($server);
        $entity->setToken('foobar');
        $entity->setExpireTime($time);
        $entity->setSession((new Session($server)));
        $entity->associateScope((new Scope($server))->setId('foo'));

        $this->assertEquals('foobar', $entity->getToken());
        $this->assertEquals($time, $entity->getExpireTime());
        $this->assertTrue($entity->getSession() instanceof Session);
        $this->assertTrue($entity->hasScope('foo'));

        $result = $entity->getScopes();
        $this->assertTrue(isset($result['foo']));
    }

    public function testGetSession()
    {
        $server = new Authorization();

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getByAccessToken')->andReturn(
            (new Session($server))
        );
        $sessionStorage->shouldReceive('setServer');

        $server->setSessionStorage($sessionStorage);

        $entity = new StubAbstractToken($server);
        $this->assertTrue($entity->getSession() instanceof Session);
    }

    public function testGetScopes()
    {
        $server = new Authorization();

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn(
            []
        );
        $accessTokenStorage->shouldReceive('setServer');

        $server->setAccessTokenStorage($accessTokenStorage);

        $entity = new StubAbstractToken($server);
        $this->assertEquals($entity->getScopes(), []);
    }

    public function testHasScopes()
    {
        $server = new Authorization();

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn(
            []
        );
        $accessTokenStorage->shouldReceive('setServer');

        $server->setAccessTokenStorage($accessTokenStorage);

        $entity = new StubAbstractToken($server);
        $this->assertFalse($entity->hasScope('foo'));
    }

    public function testFormatScopes()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');

        $entity = new StubAbstractToken($server);
        $reflectedEntity = new \ReflectionClass('LeagueTests\Stubs\StubAbstractToken');
        $method = $reflectedEntity->getMethod('formatScopes');
        $method->setAccessible(true);

        $scopes = [
            (new Scope($server))->setId('scope1')->setDescription('foo'),
            (new Scope($server))->setId('scope2')->setDescription('bar')
        ];

        $result = $method->invokeArgs($entity, [$scopes]);

        $this->assertTrue(isset($result['scope1']));
        $this->assertTrue(isset($result['scope2']));
        $this->assertTrue($result['scope1'] instanceof Scope);
        $this->assertTrue($result['scope2'] instanceof Scope);
    }
}
