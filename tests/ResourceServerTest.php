<?php

namespace LeagueTests;

use League\OAuth2\Server\ResourceServer;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Entity\ClientEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use \Mockery as M;

class ResourceServerTest extends \PHPUnit_Framework_TestCase
{
    private function returnDefault()
    {
        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');

        $server = new ResourceServer(
            $sessionStorage,
            $accessTokenStorage,
            $clientStorage,
            $scopeStorage
        );

        return $server;
    }

    function testGetSet()
    {
        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');

        $server = new ResourceServer(
            $sessionStorage,
            $accessTokenStorage,
            $clientStorage,
            $scopeStorage
        );
    }

    public function testDetermineAccessTokenMissingToken()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('get')->andReturn(false);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');

        $server = new ResourceServer(
            $sessionStorage,
            $accessTokenStorage,
            $clientStorage,
            $scopeStorage
        );

        $request = new \Symfony\Component\HttpFoundation\Request();
        $request->headers = new \Symfony\Component\HttpFoundation\ParameterBag([
            'HTTP_AUTHORIZATION' =>  'Bearer'
        ]);
        $server->setRequest($request);

        $reflector = new \ReflectionClass($server);
        $method = $reflector->getMethod('determineAccessToken');
        $method->setAccessible(true);

        $method->invoke($server);
    }

    public function testIsValidNotValid()
    {
        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('get')->andReturn(false);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');

        $server = new ResourceServer(
            $sessionStorage,
            $accessTokenStorage,
            $clientStorage,
            $scopeStorage
        );

        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');
        $server->isValidRequest();
    }

    public function testIsValid()
    {
        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');

        $server = new ResourceServer(
            $sessionStorage,
            $accessTokenStorage,
            $clientStorage,
            $scopeStorage
        );

        $server->setTokenKey('at');

        $accessTokenStorage->shouldReceive('get')->andReturn(
            (new AccessTokenEntity($server))->setToken('abcdef')
        );

        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->setId('foo'),
            (new ScopeEntity($server))->setId('bar')
        ]);

        $sessionStorage->shouldReceive('getByAccessToken')->andReturn(
            (new SessionEntity($server))->setId('foobar')->setOwner('user', 123)
        );

        $clientStorage->shouldReceive('getBySession')->andReturn(
            (new ClientEntity($server))->setId('testapp')
        );

        $request = new \Symfony\Component\HttpFoundation\Request();
        $request->headers = new \Symfony\Component\HttpFoundation\ParameterBag([
            'Authorization' =>  'Bearer abcdef'
        ]);
        $server->setRequest($request);

        $this->assertTrue($server->isValidRequest());
        $this->assertEquals('at', $server->getTokenKey());
        $this->assertEquals(123, $server->getOwnerId());
        $this->assertEquals('user', $server->getOwnerType());
        $this->assertEquals('abcdef', $server->getAccessToken());
        $this->assertEquals('testapp', $server->getClientId());
        $this->assertTrue($server->hasScope('foo'));
        $this->assertTrue($server->hasScope('bar'));
        $this->assertTrue($server->hasScope(['foo', 'bar']));
        $this->assertTrue(isset($server->getScopes()['foo']));
        $this->assertTrue(isset($server->getScopes()['bar']));
        $this->assertFalse($server->hasScope(['foobar']));
        $this->assertFalse($server->hasScope('foobar'));
    }
}
