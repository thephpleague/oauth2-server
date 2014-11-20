<?php

namespace LeagueTests;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\GrantTypeInterface;
use League\OAuth2\Server\Storage\ScopeInterface;
use Mockery as M;

class AuthorizationServerTest extends \PHPUnit_Framework_TestCase
{
    public function testSetGet()
    {
        $server = new AuthorizationServer();
        $server->requireScopeParam(true);
        $server->requireStateParam(true);
        $server->setDefaultScope('foobar');
        $server->setScopeDelimiter(',');
        $server->setAccessTokenTTL(1);

        $grant = M::mock('League\OAuth2\Server\Grant\GrantTypeInterface');
        $grant->shouldReceive('getIdentifier')->andReturn('foobar');
        $grant->shouldReceive('getResponseType')->andReturn('foobar');
        $grant->shouldReceive('setAuthorizationServer');

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');

        $server->addGrantType($grant);
        $server->setScopeStorage($scopeStorage);

        $this->assertTrue($server->hasGrantType('foobar'));
        $this->assertTrue($server->getGrantType('foobar') instanceof GrantTypeInterface);
        $this->assertSame($server->getResponseTypes(), ['foobar']);
        $this->assertTrue($server->scopeParamRequired());
        $this->assertTrue($server->stateParamRequired());
        $this->assertTrue($server->getScopeStorage() instanceof ScopeInterface);
        $this->assertEquals('foobar', $server->getDefaultScope());
        $this->assertEquals(',', $server->getScopeDelimiter());
        $this->assertEquals(1, $server->getAccessTokenTTL());
    }

    public function testInvalidGrantType()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidGrantException');
        $server = new AuthorizationServer();
        $server->getGrantType('foobar');
    }

    public function testIssueAccessToken()
    {
        $grant = M::mock('League\OAuth2\Server\Grant\GrantTypeInterface');
        $grant->shouldReceive('getIdentifier')->andReturn('foobar');
        $grant->shouldReceive('getResponseType')->andReturn('foobar');
        $grant->shouldReceive('setAuthorizationServer');
        $grant->shouldReceive('completeFlow')->andReturn(true);

        $_POST['grant_type'] = 'foobar';

        $server = new AuthorizationServer();
        $server->addGrantType($grant);

        $this->assertTrue($server->issueAccessToken());
    }

    public function testIssueAccessTokenEmptyGrantType()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');
        $server = new AuthorizationServer();
        $this->assertTrue($server->issueAccessToken());
    }

    public function testIssueAccessTokenInvalidGrantType()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\UnsupportedGrantTypeException');

        $_POST['grant_type'] = 'foobar';

        $server = new AuthorizationServer();
        $this->assertTrue($server->issueAccessToken());
    }
}
