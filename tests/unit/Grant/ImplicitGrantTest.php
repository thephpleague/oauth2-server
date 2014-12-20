<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entity\ClientEntity;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Grant\ImplicitGrant;
use Mockery as M;

class ImplicitGrantTest extends \PHPUnit_Framework_TestCase
{
    public function testCheckAuthorizeParamsMissingClientId()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_GET = [];

        $server = new AuthorizationServer();
        $grant = new ImplicitGrant();
        $server->addGrantType($grant);

        $grant->checkAuthorizeParams();
    }

    public function testCheckAuthorizeParamsMissingRedirectUri()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_GET = [
            'client_id' =>  'testapp',
        ];

        $server = new AuthorizationServer();
        $grant = new ImplicitGrant();
        $server->addGrantType($grant);

        $grant->checkAuthorizeParams();
    }

    public function testCheckAuthoriseParamsInvalidClient()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidClientException');

        $_GET = [
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
            'response_type' =>  'token',
        ];

        $server = new AuthorizationServer();
        $grant = new ImplicitGrant();
        $server->addGrantType($grant);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(null);
        $server->setClientStorage($clientStorage);

        $grant->checkAuthorizeParams();
    }

    public function testCheckAuthoriseParamsMissingStateParam()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_GET = [
            'client_id' =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
        ];

        $server = new AuthorizationServer();
        $grant = new ImplicitGrant();
        $server->addGrantType($grant);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );
        $server->setClientStorage($clientStorage);

        $server->requireStateParam(true);

        $grant->checkAuthorizeParams();
    }

    public function testCheckAuthoriseParamsMissingResponseType()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_GET = [
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
        ];

        $server = new AuthorizationServer();
        $grant = new ImplicitGrant();
        $server->addGrantType($grant);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );
        $server->setClientStorage($clientStorage);

        $grant->checkAuthorizeParams();
    }

    public function testCheckAuthoriseParamsInvalidResponseType()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\UnsupportedResponseTypeException');

        $_GET = [
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
            'response_type' =>  'foobar',
        ];
        $server = new AuthorizationServer();
        $grant = new ImplicitGrant();
        $server->addGrantType($grant);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );
        $server->setClientStorage($clientStorage);

        $grant->checkAuthorizeParams();
    }

    public function testCheckAuthoriseParamsInvalidScope()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidScopeException');

        $_GET = [
            'response_type' =>  'token',
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
            'scope'         =>  'foo',
        ];

        $server = new AuthorizationServer();
        $grant = new ImplicitGrant();
        $server->addGrantType($grant);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('create');
        $sessionStorage->shouldReceive('getScopes')->andReturn([]);

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('create');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([]);

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(null);

        $server->setClientStorage($clientStorage);
        $server->setScopeStorage($scopeStorage);
        $server->setSessionStorage($sessionStorage);
        $server->setAccessTokenStorage($accessTokenStorage);

        $grant->checkAuthorizeParams();
    }

    public function testCheckAuthoriseParams()
    {
        $_GET = [
            'response_type' =>  'token',
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
            'scope'         =>  'foo',
            ];

        $server = new AuthorizationServer();
        $grant = new ImplicitGrant();
        $server->addGrantType($grant);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('create')->andreturn(123);
        $sessionStorage->shouldReceive('getScopes')->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo']),
        ]);
        $sessionStorage->shouldReceive('associateScope');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('create');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo']),
        ]);
        $accessTokenStorage->shouldReceive('associateScope');

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        );

        $server->setClientStorage($clientStorage);
        $server->setScopeStorage($scopeStorage);
        $server->setSessionStorage($sessionStorage);
        $server->setAccessTokenStorage($accessTokenStorage);

        $result = $grant->checkAuthorizeParams();

        $this->assertTrue($result['client'] instanceof ClientEntity);
        $this->assertTrue($result['redirect_uri'] === $_GET['redirect_uri']);
        $this->assertTrue($result['state'] === null);
        $this->assertTrue($result['response_type'] === 'token');
        $this->assertTrue($result['scopes']['foo'] instanceof ScopeEntity);
    }

    public function testGetRedirectURIMissingClient()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidClientException');

        $server = new AuthorizationServer();
        $grant = new ImplicitGrant();
        $server->addGrantType($grant);

        $params = [
            'client' => null,
        ];

        $grant->getRedirectUri($params);
    }

    public function testGetRedirectURIMissingRedirectURI()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $server = new AuthorizationServer();
        $grant = new ImplicitGrant();
        $server->addGrantType($grant);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );
        $server->setClientStorage($clientStorage);

        $params = [
            'client' => $clientStorage->get('testapp'),
        ];

        $grant->getRedirectUri($params);
    }

    public function testGetRedirectURI()
    {
        $_GET = [
            'response_type' =>  'token',
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
            'scope'         =>  'foo',
            ];

        $server = new AuthorizationServer();
        $grant = new ImplicitGrant();
        $server->addGrantType($grant);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('create')->andreturn(123);
        $sessionStorage->shouldReceive('getScopes')->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo']),
        ]);
        $sessionStorage->shouldReceive('associateScope');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('create');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo']),
        ]);
        $accessTokenStorage->shouldReceive('associateScope');

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        );

        $server->setClientStorage($clientStorage);
        $server->setScopeStorage($scopeStorage);
        $server->setSessionStorage($sessionStorage);
        $server->setAccessTokenStorage($accessTokenStorage);

        $result = $grant->checkAuthorizeParams();
        $uri = $grant->getRedirectUri($result);
        $this->assertGreaterThanOrEqual(1, preg_match('#http://foo/bar\#access_token=[a-zA-Z0-9]{40}&token_type=Bearer&expires_in=3600#', $uri));
    }
}
