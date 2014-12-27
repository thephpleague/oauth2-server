<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entity\ClientEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Exception\InvalidRequestException;
use League\OAuth2\Server\Grant;
use LeagueTests\Stubs\StubAbstractGrant;
use Mockery as M;

class AbstractGrantTest extends \PHPUnit_Framework_TestCase
{
    public function testSetGet()
    {
        $server = new AuthorizationServer();

        $grant = new StubAbstractGrant();
        $grant->setIdentifier('foobar');
        $grant->setAccessTokenTTL(300);
        $grant->setAuthorizationServer($server);

        $this->assertEquals('foobar', $grant->getIdentifier());
        $this->assertEquals('foobar', $grant->getResponseType());
        $this->assertEquals(300, $grant->getAccessTokenTTL());
        $this->assertTrue($grant->getAuthorizationServer() instanceof AuthorizationServer);
    }

    public function testFormatScopes()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');

        $grant = new StubAbstractGrant();
        $reflectedGrant = new \ReflectionClass('LeagueTests\Stubs\StubAbstractGrant');
        $method = $reflectedGrant->getMethod('formatScopes');
        $method->setAccessible(true);

        $scopes = [
            (new ScopeEntity($server))->setId('scope1')->setDescription('foo'),
            (new ScopeEntity($server))->setId('scope2')->setDescription('bar'),
        ];

        $result = $method->invokeArgs($grant, [$scopes]);

        $this->assertTrue(isset($result['scope1']));
        $this->assertTrue(isset($result['scope2']));
        $this->assertTrue($result['scope1'] instanceof ScopeEntity);
        $this->assertTrue($result['scope2'] instanceof ScopeEntity);
    }

    public function testValidateScopes()
    {
        $server = new AuthorizationServer();

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(
            (new ScopeEntity($server))->setId('foo')
        );

        $server->setScopeStorage($scopeStorage);

        $grant = new StubAbstractGrant();
        $grant->setAuthorizationServer($server);

        $client = (new ClientEntity($server))->setId('testapp');

        $this->assertEquals(
            [
                'foo' => (new ScopeEntity($server))->setId('foo'),
            ],
            $grant->validateScopes('foo', $client)
        );
    }

    public function testValidateScopesMissingScope()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');

        $server = new AuthorizationServer();
        $server->requireScopeParam(true);
        $server->setScopeStorage($scopeStorage);

        $grant = new StubAbstractGrant();
        $grant->setAuthorizationServer($server);

        $client = (new ClientEntity($server))->setId('testapp');

        $grant->validateScopes(null, $client);
    }

    public function testValidateScopesInvalidScope()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidScopeException');

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(null);

        $server = new AuthorizationServer();
        $server->setScopeStorage($scopeStorage);

        $grant = new StubAbstractGrant();
        $grant->setAuthorizationServer($server);

        $client = (new ClientEntity($server))->setId('testapp');

        $grant->validateScopes('blah', $client);
    }

    public function testValidateScopesDefaultScope()
    {
        $server = new AuthorizationServer();

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(
            (new ScopeEntity($server))->setId('foo')
        );
        $server->setScopeStorage($scopeStorage);

        $server->requireScopeParam(true);
        $server->setScopeStorage($scopeStorage);
        $server->setDefaultScope('foo');

        $grant = new StubAbstractGrant();
        $grant->setAuthorizationServer($server);

        $client = (new ClientEntity($server))->setId('testapp');

        $grant->validateScopes(null, $client);
    }

    public function testValidateScopesDefaultScopeArray()
    {
        $server = new AuthorizationServer();

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(
            (new ScopeEntity($server))->setId('foo')
        );
        $server->setScopeStorage($scopeStorage);

        $server->requireScopeParam(true);
        $server->setScopeStorage($scopeStorage);
        $server->setDefaultScope(['foo', 'bar']);

        $grant = new StubAbstractGrant();
        $grant->setAuthorizationServer($server);

        $client = (new ClientEntity($server))->setId('testapp');

        $grant->validateScopes(null, $client);
    }
}
