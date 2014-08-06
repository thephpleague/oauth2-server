<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\ClientEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Entity\AuthCodeEntity;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\InvalidRequestException;
use Mockery as M;

class AuthCodeGrantTest extends \PHPUnit_Framework_TestCase
{
    public function testSetAuthTokenTTL()
    {
        $grant = new AuthCodeGrant;
        $grant->setAuthTokenTTL(100);

        $class = new \ReflectionClass($grant);
        $property = $class->getProperty('authTokenTTL');
        $property->setAccessible(true);
        $this->assertEquals(100, $property->getValue($grant));
    }

    public function testCheckAuthoriseParamsMissingClientId()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_GET = [];
        $server = new AuthorizationServer;

        $grant = new AuthCodeGrant;

        $server->addGrantType($grant);
        $grant->checkAuthorizeParams();

    }

    public function testCheckAuthoriseParamsMissingRedirectUri()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $server = new AuthorizationServer;
        $_GET = [
            'client_id' =>  'testapp'
        ];

        $grant = new AuthCodeGrant;

        $server->addGrantType($grant);
        $grant->checkAuthorizeParams();
    }

    public function testCheckAuthoriseParamsMissingStateParam()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_GET = [
            'client_id' =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar'
        ];
        $server = new AuthorizationServer;

        $grant = new AuthCodeGrant;
        $server->requireStateParam(true);

        $server->addGrantType($grant);
        $grant->checkAuthorizeParams();
    }

    public function testCheckAuthoriseParamsMissingResponseType()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_GET = [
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar'
        ];
        $server = new AuthorizationServer;

        $grant = new AuthCodeGrant;

        $server->addGrantType($grant);
        $grant->checkAuthorizeParams();
    }

    public function testCheckAuthoriseParamsInvalidResponseType()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\UnsupportedResponseTypeException');

        $_GET = [
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
            'response_type' =>  'foobar'
        ];
        $server = new AuthorizationServer;

        $grant = new AuthCodeGrant;

        $server->addGrantType($grant);
        $grant->checkAuthorizeParams();
    }

    public function testCheckAuthoriseParamsInvalidClient()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidClientException');

        $_GET = [
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
            'response_type' =>  'code'
        ];
        $server = new AuthorizationServer;

        $grant = new AuthCodeGrant;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(null);

        $server->setClientStorage($clientStorage);

        $server->addGrantType($grant);
        $grant->checkAuthorizeParams();
    }

    public function testCheckAuthoriseParamsInvalidScope()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidScopeException');

        $_GET = [
            'response_type' =>  'code',
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
            'scope'         =>  'foo'
        ];

        $server = new AuthorizationServer;
        $grant = new AuthCodeGrant;

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

        $server->addGrantType($grant);
        $grant->checkAuthorizeParams();
    }

    public function testCheckAuthoriseParams()
    {
        $_GET = [
            'response_type' =>  'code',
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
            'scope'         =>  'foo'
        ];

        $server = new AuthorizationServer;
        $grant = new AuthCodeGrant;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('create')->andreturn(123);
        $sessionStorage->shouldReceive('getScopes')->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        ]);
        $sessionStorage->shouldReceive('associateScope');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('create');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
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

        $server->addGrantType($grant);

        $result = $grant->checkAuthorizeParams();

        $this->assertTrue($result['client'] instanceof ClientEntity);
        $this->assertTrue($result['redirect_uri'] === $_GET['redirect_uri']);
        $this->assertTrue($result['state'] === null);
        $this->assertTrue($result['response_type'] === 'code');
        $this->assertTrue($result['scopes']['foo'] instanceof ScopeEntity);
    }

    public function testNewAuthoriseRequest()
    {
        $server = new AuthorizationServer;
        $client = (new ClientEntity($server))->hydrate(['id' => 'testapp']);
        $scope = (new ScopeEntity($server))->hydrate(['id' => 'foo']);

        $grant = new AuthCodeGrant;
        $server->addGrantType($grant);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('create')->andreturn(123);
        $sessionStorage->shouldReceive('getScopes')->shouldReceive('getScopes')->andReturn([$scope]);
        $sessionStorage->shouldReceive('associateScope');
        $server->setSessionStorage($sessionStorage);

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('setServer');
        $authCodeStorage->shouldReceive('get');
        $authCodeStorage->shouldReceive('create');
        $authCodeStorage->shouldReceive('associateScope');
        $server->setAuthCodeStorage($authCodeStorage);

        $grant->newAuthorizeRequest('user', 123, [
            'client'        => $client,
            'redirect_uri'  =>  'http://foo/bar',
            'scopes'        =>  [$scope],
            'state'         =>  'foobar'
        ]);
    }

    public function testCompleteFlowMissingClientId()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST['grant_type'] = 'authorization_code';

        $server = new AuthorizationServer;
        $grant = new AuthCodeGrant;

        $server->addGrantType($grant);
        $server->issueAccessToken();

    }

    public function testCompleteFlowMissingClientSecret()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST = [
            'grant_type' => 'authorization_code',
            'client_id' =>  'testapp'
        ];

        $server = new AuthorizationServer;
        $grant = new AuthCodeGrant;

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    public function testCompleteFlowMissingRedirectUri()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST = [
            'grant_type' => 'authorization_code',
            'client_id' =>  'testapp',
            'client_secret' => 'foobar'
        ];

        $server = new AuthorizationServer;
        $grant = new AuthCodeGrant;

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    public function testCompleteFlowInvalidClient()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidClientException');

        $_POST = [
            'grant_type'    =>  'authorization_code',
            'client_id'     =>  'testapp',
            'client_secret' =>  'foobar',
            'redirect_uri'  =>  'http://foo/bar'
        ];

        $server = new AuthorizationServer;
        $grant = new AuthCodeGrant;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(null);

        $server->setClientStorage($clientStorage);

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    public function testCompleteFlowMissingCode()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST = [
            'grant_type'    =>  'authorization_code',
            'client_id'     =>  'testapp',
            'client_secret' =>  'foobar',
            'redirect_uri'  =>  'http://foo/bar'
        ];

        $server = new AuthorizationServer;
        $grant = new AuthCodeGrant;

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

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('setServer');
        $authCodeStorage->shouldReceive('get');

        $server->setClientStorage($clientStorage);
        $server->setScopeStorage($scopeStorage);
        $server->setSessionStorage($sessionStorage);
        $server->setAccessTokenStorage($accessTokenStorage);
        $server->setAuthCodeStorage($authCodeStorage);

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    public function testCompleteFlowInvalidCode()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST = [
            'grant_type'    =>  'authorization_code',
            'client_id'     =>  'testapp',
            'client_secret' =>  'foobar',
            'redirect_uri'  =>  'http://foo/bar',
            'code'          =>  'foobar'
        ];

        $server = new AuthorizationServer;
        $grant = new AuthCodeGrant;

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

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('setServer');
        $authCodeStorage->shouldReceive('get');

        $server->setClientStorage($clientStorage);
        $server->setScopeStorage($scopeStorage);
        $server->setSessionStorage($sessionStorage);
        $server->setAccessTokenStorage($accessTokenStorage);
        $server->setAuthCodeStorage($authCodeStorage);

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    public function testCompleteFlowRedirectUriMismatch()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST = [
            'grant_type'    =>  'authorization_code',
            'client_id'     =>  'testapp',
            'client_secret' =>  'foobar',
            'redirect_uri'  =>  'http://foo/bar',
            'code'          =>  'foobar'
        ];

        $server = new AuthorizationServer;
        $grant = new AuthCodeGrant;

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

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('setServer');
        $authCodeStorage->shouldReceive('get')->andReturn(
            (new AuthCodeEntity($server))->setId('foobar')->setRedirectUri('http://fail/face')
        );

        $server->setClientStorage($clientStorage);
        $server->setScopeStorage($scopeStorage);
        $server->setSessionStorage($sessionStorage);
        $server->setAccessTokenStorage($accessTokenStorage);
        $server->setAuthCodeStorage($authCodeStorage);

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    public function testCompleteFlow()
    {
        $_POST = [
            'grant_type'    => 'authorization_code',
            'client_id'     =>  'testapp',
            'client_secret' =>  'foobar',
            'redirect_uri'  =>  'http://foo/bar',
            'code'          =>  'foo'
        ];

        $server = new AuthorizationServer;
        $grant = new AuthCodeGrant;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('getBySession')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );
        $clientStorage->shouldReceive('get')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('create')->andreturn(123);
        $sessionStorage->shouldReceive('associateScope');
        $sessionStorage->shouldReceive('getByAuthCode')->andReturn(
            (new SessionEntity($server))->setId('foobar')
        );
        $sessionStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        ]);

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('create');
        $accessTokenStorage->shouldReceive('associateScope');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        ]);

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        );

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('setServer');
        $authCodeStorage->shouldReceive('delete');
        $authCodeStorage->shouldReceive('get')->andReturn(
            (new AuthCodeEntity($server))->setId('foobar')->setRedirectUri('http://foo/bar')
        );
        $authCodeStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        ]);

        $server->setClientStorage($clientStorage);
        $server->setScopeStorage($scopeStorage);
        $server->setSessionStorage($sessionStorage);
        $server->setAccessTokenStorage($accessTokenStorage);
        $server->setAuthCodeStorage($authCodeStorage);

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    public function testCompleteFlowWithRefreshToken()
    {
        $_POST = [
            'grant_type'    => 'authorization_code',
            'client_id'     =>  'testapp',
            'client_secret' =>  'foobar',
            'redirect_uri'  =>  'http://foo/bar',
            'code'          =>  'foo'
        ];

        $server = new AuthorizationServer;
        $grant = new AuthCodeGrant;
        $rtgrant = new RefreshTokenGrant;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('getBySession')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );
        $clientStorage->shouldReceive('get')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('create')->andreturn(123);
        $sessionStorage->shouldReceive('associateScope');
        $sessionStorage->shouldReceive('getByAuthCode')->andReturn(
            (new SessionEntity($server))->setId('foobar')
        );
        $sessionStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        ]);

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('create');
        $accessTokenStorage->shouldReceive('associateScope');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        ]);

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        );

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('setServer');
        $authCodeStorage->shouldReceive('delete');
        $authCodeStorage->shouldReceive('get')->andReturn(
            (new AuthCodeEntity($server))->setId('foobar')->setRedirectUri('http://foo/bar')
        );
        $authCodeStorage->shouldReceive('getScopes')->andReturn([
            (new ScopeEntity($server))->hydrate(['id' => 'foo'])
        ]);

        $refreshTokenStorage = M::mock('League\OAuth2\Server\Storage\RefreshTokenInterface');
        $refreshTokenStorage->shouldReceive('setServer');
        $refreshTokenStorage->shouldReceive('create');
        $refreshTokenStorage->shouldReceive('associateScope');

        $server->setClientStorage($clientStorage);
        $server->setScopeStorage($scopeStorage);
        $server->setSessionStorage($sessionStorage);
        $server->setAccessTokenStorage($accessTokenStorage);
        $server->setAuthCodeStorage($authCodeStorage);
        $server->setRefreshTokenStorage($refreshTokenStorage);

        $server->addGrantType($grant);
        $server->addGrantType($rtgrant);
        $server->issueAccessToken();
    }
}
