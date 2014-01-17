<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\Grant;
use League\OAuth2\Server\Entity\Scope;
use League\OAuth2\Server\Authorization;
use League\OAuth2\Server\Grant\ClientException;
use LeagueTests\Stubs\StubAbstractGrant;
use Mockery as M;

class AbstractGrantTest extends \PHPUnit_Framework_TestCase
{
    function testSetGet()
    {
        $server = new Authorization;

        $grant = new StubAbstractGrant;
        $grant->setIdentifier('foobar');
        $grant->setAccessTokenTTL(300);
        $grant->setAuthorizationServer($server);

        $this->assertEquals('foobar', $grant->getIdentifier());
        $this->assertEquals('foobar', $grant->getResponseType());
        $this->assertEquals(300, $grant->getAccessTokenTTL());
        $this->assertTrue($grant->getAuthorizationServer() instanceof Authorization);
    }

    public function testFormatScopes()
    {
        $server = M::mock('League\OAuth2\Server\AbstractServer');

        $grant = new StubAbstractGrant;
        $reflectedGrant = new \ReflectionClass('LeagueTests\Stubs\StubAbstractGrant');
        $method = $reflectedGrant->getMethod('formatScopes');
        $method->setAccessible(true);

        $scopes = [
            (new Scope($server))->setId('scope1')->setDescription('foo'),
            (new Scope($server))->setId('scope2')->setDescription('bar')
        ];

        $result = $method->invokeArgs($grant, [$scopes]);

        $this->assertTrue(isset($result['scope1']));
        $this->assertTrue(isset($result['scope2']));
        $this->assertTrue($result['scope1'] instanceof Scope);
        $this->assertTrue($result['scope2'] instanceof Scope);
    }

    public function testValidateScopes()
    {
        $server = new Authorization;

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(
            (new Scope($server))->setId('foo')
        );

        $server->setScopeStorage($scopeStorage);

        $grant = new StubAbstractGrant;
        $grant->setAuthorizationServer($server);

        $this->assertEquals(
            [
                'foo'   =>  (new Scope($server))->setId('foo')
            ],

            $grant->validateScopes('foo')
        );
    }

    public function testValidateScopesMissingScope()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\ClientException');

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');

        $server = new Authorization;
        $server->requireScopeParam(true);
        $server->setScopeStorage($scopeStorage);

        $grant = new StubAbstractGrant;
        $grant->setAuthorizationServer($server);

        $grant->validateScopes();
    }

    public function testValidateScopesInvalidScope()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\ClientException');

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(null);

        $server = new Authorization;
        $server->setScopeStorage($scopeStorage);

        $grant = new StubAbstractGrant;
        $grant->setAuthorizationServer($server);

        $grant->validateScopes('blah');
    }

    public function testValidateScopesDefaultScope()
    {
        $server = new Authorization;

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(
            (new Scope($server))->setId('foo')
        );
        $server->setScopeStorage($scopeStorage);

        $server->requireScopeParam(true);
        $server->setScopeStorage($scopeStorage);
        $server->setDefaultScope('foo');

        $grant = new StubAbstractGrant;
        $grant->setAuthorizationServer($server);

        $grant->validateScopes();
    }

    public function testValidateScopesDefaultScopeArray()
    {
        $server = new Authorization;

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(
            (new Scope($server))->setId('foo')
        );
        $server->setScopeStorage($scopeStorage);

        $server->requireScopeParam(true);
        $server->setScopeStorage($scopeStorage);
        $server->setDefaultScope(['foo', 'bar']);

        $grant = new StubAbstractGrant;
        $grant->setAuthorizationServer($server);

        $grant->validateScopes();
    }
}
