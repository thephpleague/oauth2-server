<?php

namespace LeagueTests\Entities;

use League\OAuth2\Server\Entity\Scope;
use League\OAuth2\Server\Entity\Session;
use League\OAuth2\Server\Entity\AccessToken;
use League\OAuth2\Server\Entity\RefreshToken;
use League\OAuth2\Server\Authorization;
use \Mockery as M;

class RefreshTokenTests extends \PHPUnit_Framework_TestCase
{
    function testSetAccessToken()
    {
        $reader = function & ($object, $property) {
            $value = & \Closure::bind(function & () use ($property) {
                return $this->$property;
            }, $object, $object)->__invoke();

            return $value;
        };

        $server = M::mock('League\OAuth2\Server\AbstractServer');
        $entity = new RefreshToken($server);
        $entity->setAccessToken((new AccessToken($server)));

        $this->assertTrue($reader($entity, 'accessToken') instanceof AccessToken);
    }

    function testSave()
    {
        $server = new Authorization();

        $refreshTokenStorage = M::mock('League\OAuth2\Server\Storage\RefreshTokenInterface');
        $refreshTokenStorage->shouldReceive('create');
        $refreshTokenStorage->shouldReceive('setServer');
        $refreshTokenStorage->shouldReceive('associateScope');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('getByRefreshToken')->andReturn(
            (new AccessToken($server))->setToken('foobar')
        );
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new Scope($server))->setId('foo')
        ]);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('getByAccessToken')->andReturn(
            (new Session($server))
        );
        $sessionStorage->shouldReceive('setServer');

        $server->setAccessTokenStorage($accessTokenStorage);
        $server->setRefreshTokenStorage($refreshTokenStorage);

        $entity = new RefreshToken($server);
        $this->assertSame(null, $entity->save());
    }

    function testExpire()
    {
        $server = new Authorization();

        $refreshTokenStorage = M::mock('League\OAuth2\Server\Storage\RefreshTokenInterface');
        $refreshTokenStorage->shouldReceive('delete');
        $refreshTokenStorage->shouldReceive('setServer');

        $server->setRefreshTokenStorage($refreshTokenStorage);

        $entity = new RefreshToken($server);
        $this->assertSame($entity->expire(), null);
    }
}
