<?php

namespace LeagueTests\Entities;

use League\OAuth2\Server\Entity\AccessToken;
use League\OAuth2\Server\Entity\AuthCode;
use League\OAuth2\Server\Entity\Client;
use League\OAuth2\Server\Entity\RefreshToken;
use League\OAuth2\Server\Entity\Session;
use League\OAuth2\Server\Entity\Scope;
use League\OAuth2\Server\Authorization;
use \Mockery as M;

class SessionTests extends \PHPUnit_Framework_TestCase
{
    public function testSetGet()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $entity = new Session($server);
        $entity->setId('foobar');
        $entity->setOwner('user', 123);
        $entity->associateAccessToken((new AccessToken($server)));
        $entity->associateRefreshToken((new RefreshToken($server)));
        $entity->associateClient((new Client($server)));
        $entity->associateScope((new Scope($server))->setId('foo'));
        // $entity->associateAuthCode((new AuthCode($server)));

        $this->assertEquals('foobar', $entity->getId());
        $this->assertEquals('user', $entity->getOwnerType());
        $this->assertEquals(123, $entity->getOwnerId());
        $this->assertTrue($entity->getClient() instanceof Client);
        $this->assertTrue($entity->hasScope('foo'));

        $reflector = new \ReflectionClass($entity);
        $accessTokenProperty = $reflector->getProperty('accessToken');
        $accessTokenProperty->setAccessible(true);
        $refreshTokenProperty = $reflector->getProperty('refreshToken');
        $refreshTokenProperty->setAccessible(true);

        $this->assertTrue($accessTokenProperty->getValue($entity) instanceof AccessToken);
        $this->assertTrue($refreshTokenProperty->getValue($entity) instanceof RefreshToken);
        // $this->assertTrue($reader($entity, 'authCode') instanceof AuthCode);
    }

    public function testFormatScopes()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');

        $entity = new Session($server);
        $reflectedEntity = new \ReflectionClass('League\OAuth2\Server\Entity\Session');
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

    public function testGetScopes()
    {
        $server = new Authorization();

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $server->setAccessTokenStorage($accessTokenStorage);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getScopes')->andReturn(
            []
        );
        $sessionStorage->shouldReceive('setServer');
        $server->setSessionStorage($sessionStorage);

        $entity = new Session($server);
        $this->assertEquals($entity->getScopes(), []);
    }

    public function testHasScopes()
    {
        $server = new Authorization();

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $server->setAccessTokenStorage($accessTokenStorage);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getScopes')->andReturn(
            []
        );
        $sessionStorage->shouldReceive('setServer');
        $server->setSessionStorage($sessionStorage);

        $entity = new Session($server);
        $this->assertFalse($entity->hasScope('foo'));
    }

    function testSave()
    {
        $server = new Authorization();

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('create');
        $sessionStorage->shouldReceive('associateScope');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('getScopes')->andReturn([
            (new Scope($server))->setId('foo')
        ]);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('getBySession')->andReturn(
            (new Client($server))->setId('foo')
        );
        $clientStorage->shouldReceive('setServer');

        $server->setSessionStorage($sessionStorage);
        $server->setClientStorage($clientStorage);

        $entity = new Session($server);
        $this->assertEquals(null, $entity->save());
    }
}