<?php

namespace LeagueTests\Entity;

use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\ClientEntity;
use League\OAuth2\Server\Entity\RefreshTokenEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\AuthorizationServer;
use \Mockery as M;

class SessionTest extends \PHPUnit_Framework_TestCase
{
    public function testSetGet()
    {
        $emitter = M::mock('League\Event\Emitter');
        $emitter->shouldReceive('emit');
        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $server->shouldReceive('setEventEmitter');
        $server->shouldReceive('getEventEmitter')->andReturn($emitter);
        $server->setEventEmitter($emitter);

        $entity = new SessionEntity($server);
        $entity->setId('foobar');
        $entity->setOwner('user', 123);
        $entity->associateAccessToken((new AccessTokenEntity($server)));
        $entity->associateRefreshToken((new RefreshTokenEntity($server)));
        $entity->associateClient((new ClientEntity($server)));
        $entity->associateScope(
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        );
        // $entity->associateAuthCode((new AuthCode($server)));

        $this->assertEquals('foobar', $entity->getId());
        $this->assertEquals('user', $entity->getOwnerType());
        $this->assertEquals(123, $entity->getOwnerId());
        $this->assertTrue($entity->getClient() instanceof ClientEntity);
        $this->assertTrue($entity->hasScope('foo'));

        $reflector = new \ReflectionClass($entity);
        $accessTokenProperty = $reflector->getProperty('accessToken');
        $accessTokenProperty->setAccessible(true);
        $refreshTokenProperty = $reflector->getProperty('refreshToken');
        $refreshTokenProperty->setAccessible(true);

        $this->assertTrue($accessTokenProperty->getValue($entity) instanceof AccessTokenEntity);
        $this->assertTrue($refreshTokenProperty->getValue($entity) instanceof RefreshTokenEntity);
        // $this->assertTrue($reader($entity, 'authCode') instanceof AuthCode);
    }

    public function testFormatScopes()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');

        $entity = new SessionEntity($server);
        $reflectedEntity = new \ReflectionClass('League\OAuth2\Server\Entity\SessionEntity');
        $method = $reflectedEntity->getMethod('formatScopes');
        $method->setAccessible(true);

        $scopes = [
            (new ScopeEntity($server))->hydrate(['id' => 'scope1']),
            (new ScopeEntity($server))->hydrate(['id' => 'scope2'])
        ];

        $result = $method->invokeArgs($entity, [$scopes]);

        $this->assertTrue(isset($result['scope1']));
        $this->assertTrue(isset($result['scope2']));
        $this->assertTrue($result['scope1'] instanceof ScopeEntity);
        $this->assertTrue($result['scope2'] instanceof ScopeEntity);
    }

    public function testGetScopes()
    {
        $server = M::mock('League\OAuth2\Server\AuthorizationServer');
        $server->shouldReceive('setAccessTokenStorage');
        $server->shouldReceive('setSessionStorage');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $server->setAccessTokenStorage($accessTokenStorage);

        $server->shouldReceive('getAccessTokenStorage')->andReturn($accessTokenStorage);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getScopes')->andReturn(
            []
        );
        $sessionStorage->shouldReceive('setServer');
        $server->setSessionStorage($sessionStorage);

        $server->shouldReceive('getSessionStorage')->andReturn($sessionStorage);

        $entity = new SessionEntity($server);
        $this->assertEquals($entity->getScopes(), []);
    }

    public function testHasScopes()
    {
        $server = M::mock('League\OAuth2\Server\AuthorizationServer');
        $server->shouldReceive('setAccessTokenStorage');
        $server->shouldReceive('setSessionStorage');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $server->setAccessTokenStorage($accessTokenStorage);

        $server->shouldReceive('getAccessTokenStorage')->andReturn($accessTokenStorage);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getScopes')->andReturn(
            []
        );
        $sessionStorage->shouldReceive('setServer');
        $server->setSessionStorage($sessionStorage);

        $server->shouldReceive('getSessionStorage')->andReturn($sessionStorage);

        $entity = new SessionEntity($server);
        $this->assertFalse($entity->hasScope('foo'));
    }

    public function testSave()
    {
        $server = M::mock('League\OAuth2\Server\AuthorizationServer');
        $server->shouldReceive('setSessionStorage');
        $server->shouldReceive('setClientStorage');

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('create');
        $sessionStorage->shouldReceive('associateScope');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        ]);

        $server->shouldReceive('getSessionStorage')->andReturn($sessionStorage);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('getBySession')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'foo'])
        );
        $clientStorage->shouldReceive('setServer');

        $server->shouldReceive('getClientStorage')->andReturn($clientStorage);

        $server->setSessionStorage($sessionStorage);
        $server->setClientStorage($clientStorage);

        $entity = new SessionEntity($server);
        $this->assertEquals(null, $entity->save());
    }
}
