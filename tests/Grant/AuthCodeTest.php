<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\Grant\AuthCode;
use League\OAuth2\Server\Grant\RefreshToken;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\ClientEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Entity\AuthCode as AC;
use League\OAuth2\Server\AuthorizationServer as Authorization;
use League\OAuth2\Server\Exception\InvalidRequestException;
use Mockery as M;

class AuthCodeTest extends \PHPUnit_Framework_TestCase
{
    public function testSetAuthTokenTTL()
    {
        $grant = new AuthCode;
        $grant->setAuthTokenTTL(100);

        $class = new \ReflectionClass($grant);
        $property = $class->getProperty('authTokenTTL');
        $property->setAccessible(true);
        $this->assertEquals(100, $property->getValue($grant));
    }

    public function testCheckAuthoriseParamsMissingClientId()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST = [];

        $server = new Authorization;
        $grant = new AuthCode;

        $server->addGrantType($grant);
        $grant->checkAuthoriseParams();

    }

    public function testCheckAuthoriseParamsMissingRedirectUri()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST = [
            'client_id' =>  'testapp'
        ];

        $server = new Authorization;
        $grant = new AuthCode;

        $server->addGrantType($grant);
        $grant->checkAuthoriseParams();
    }

    public function testCheckAuthoriseParamsMissingStateParam()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST = [
            'client_id' =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar'
        ];

        $server = new Authorization;
        $server->requireStateParam(true);
        $grant = new AuthCode;

        $server->addGrantType($grant);
        $grant->checkAuthoriseParams();
    }

    public function testCheckAuthoriseParamsMissingResponseType()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST = [
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar'
        ];

        $server = new Authorization;
        $grant = new AuthCode;

        $server->addGrantType($grant);
        $grant->checkAuthoriseParams();
    }

    public function testCheckAuthoriseParamsInvalidResponseType()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\UnsupportedResponseTypeException');

        $_POST = [
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
            'response_type' =>  'foobar'
        ];

        $server = new Authorization;
        $grant = new AuthCode;

        $server->addGrantType($grant);
        $grant->checkAuthoriseParams();
    }

    public function testCheckAuthoriseParamsInvalidClient()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidClientException');

        $_POST = [
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
            'response_type' =>  'code'
        ];

        $server = new Authorization;
        $grant = new AuthCode;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(null);

        $server->setClientStorage($clientStorage);

        $server->addGrantType($grant);
        $grant->checkAuthoriseParams();
    }

    public function testCheckAuthoriseParamsInvalidScope()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidScopeException');

        $_POST = [
            'response_type' =>  'code',
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
            'scope'         =>  'foo'
        ];

        $server = new Authorization;
        $grant = new AuthCode;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new Client($server))->setId('testapp')
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
        $grant->checkAuthoriseParams();
    }

    public function testCheckAuthoriseParams()
    {
        $_POST = [
            'response_type' =>  'code',
            'client_id'     =>  'testapp',
            'redirect_uri'  =>  'http://foo/bar',
            'scope'         =>  'foo'
        ];

        $server = new Authorization;
        $grant = new AuthCode;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new Client($server))->setId('testapp')
        );

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('create')->andreturn(123);
        $sessionStorage->shouldReceive('getScopes')->shouldReceive('getScopes')->andReturn([
            (new Scope($server))->setId('foo')
        ]);
        $sessionStorage->shouldReceive('associateScope');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('create');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new Scope($server))->setId('foo')
        ]);
        $accessTokenStorage->shouldReceive('associateScope');

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(
            (new Scope($server))->setId('foo')
        );

        $server->setClientStorage($clientStorage);
        $server->setScopeStorage($scopeStorage);
        $server->setSessionStorage($sessionStorage);
        $server->setAccessTokenStorage($accessTokenStorage);

        $server->addGrantType($grant);

        $result = $grant->checkAuthoriseParams();

        $this->assertTrue($result['client'] instanceof Client);
        $this->assertTrue($result['redirect_uri'] === $_POST['redirect_uri']);
        $this->assertTrue($result['state'] === null);
        $this->assertTrue($result['response_type'] === 'code');
        $this->assertTrue($result['scopes']['foo'] instanceof Scope);
    }

    public function testNewAuthoriseRequest()
    {
        $server = new Authorization;

        $client = (new Client($server))->setId('testapp');
        $scope = (new Scope($server))->setId('foo');

        $grant = new AuthCode;
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

        $grant->newAuthoriseRequest('user', 123, [
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

        $server = new Authorization;
        $grant = new AuthCode;

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

        $server = new Authorization;
        $grant = new AuthCode;

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

        $server = new Authorization;
        $grant = new AuthCode;

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

        $server = new Authorization;
        $grant = new AuthCode;

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

        $server = new Authorization;
        $grant = new AuthCode;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new Client($server))->setId('testapp')
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

        $server = new Authorization;
        $grant = new AuthCode;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new Client($server))->setId('testapp')
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

        $server = new Authorization;
        $grant = new AuthCode;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new Client($server))->setId('testapp')
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
            (new AC($server))->setToken('foobar')->setRedirectUri('http://fail/face')
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

        $server = new Authorization;
        $grant = new AuthCode;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('getBySession')->andReturn(
            (new Client($server))->setId('testapp')
        );
        $clientStorage->shouldReceive('get')->andReturn(
            (new Client($server))->setId('testapp')
        );

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('create')->andreturn(123);
        $sessionStorage->shouldReceive('associateScope');
        $sessionStorage->shouldReceive('getByAuthCode')->andReturn(
            (new Session($server))->setId('foobar')
        );

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('create');
        $accessTokenStorage->shouldReceive('associateScope');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new Scope($server))->setId('foo')
        ]);

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(
            (new Scope($server))->setId('foo')
        );

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('setServer');
        $authCodeStorage->shouldReceive('delete');
        $authCodeStorage->shouldReceive('get')->andReturn(
            (new AC($server))->setToken('foobar')->setRedirectUri('http://foo/bar')
        );
        $authCodeStorage->shouldReceive('getScopes')->andReturn([
            (new Scope($server))->setId('foo')
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

        $server = new Authorization;
        $grant = new AuthCode;
        $rtgrant = new RefreshToken;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('getBySession')->andReturn(
            (new Client($server))->setId('testapp')
        );
        $clientStorage->shouldReceive('get')->andReturn(
            (new Client($server))->setId('testapp')
        );

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('create')->andreturn(123);
        $sessionStorage->shouldReceive('associateScope');
        $sessionStorage->shouldReceive('getByAuthCode')->andReturn(
            (new Session($server))->setId('foobar')
        );

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('create');
        $accessTokenStorage->shouldReceive('associateScope');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([
            (new Scope($server))->setId('foo')
        ]);

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');
        $scopeStorage->shouldReceive('get')->andReturn(
            (new Scope($server))->setId('foo')
        );

        $authCodeStorage = M::mock('League\OAuth2\Server\Storage\AuthCodeInterface');
        $authCodeStorage->shouldReceive('setServer');
        $authCodeStorage->shouldReceive('delete');
        $authCodeStorage->shouldReceive('get')->andReturn(
            (new AC($server))->setToken('foobar')->setRedirectUri('http://foo/bar')
        );
        $authCodeStorage->shouldReceive('getScopes')->andReturn([
            (new Scope($server))->setId('foo')
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
