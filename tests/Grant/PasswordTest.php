<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\Grant\Password;
use League\OAuth2\Server\Grant\RefreshToken;
use League\OAuth2\Server\Entity\Scope;
use League\OAuth2\Server\Entity\Client;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\ClientException;
use Mockery as M;

class PasswordTest extends \PHPUnit_Framework_TestCase
{
    function testCompleteFlowMissingClientId()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\ClientException');

        $_POST['grant_type'] = 'password';

        $server = new AuthorizationServer;
        $grant = new Password;

        $server->addGrantType($grant);
        $server->issueAccessToken();

    }

    function testCompleteFlowMissingClientSecret()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\ClientException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp'
        ];

        $server = new AuthorizationServer;
        $grant = new Password;

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    function testCompleteFlowInvalidClient()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\ClientException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar'
        ];

        $server = new AuthorizationServer;
        $grant = new Password;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(null);

        $server->setClientStorage($clientStorage);

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    function testNoUsername()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\ClientException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar'
        ];

        $server = new AuthorizationServer;
        $grant = new Password;

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
        $server->issueAccessToken();
    }

    function testNoPassword()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\ClientException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'username'  =>  'foo'
        ];

        $server = new AuthorizationServer;
        $grant = new Password;

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
        $server->issueAccessToken();
    }

    function testNoCallable()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidGrantTypeException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'username'  =>  'foo',
            'password'  =>  'foobar'
        ];

        $server = new AuthorizationServer;
        $grant = new Password;

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
        $server->issueAccessToken();
    }

    function testCompleteFlowInvalidScope()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\ClientException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'scope' => 'foo'
        ];

        $server = new AuthorizationServer;
        $grant = new Password;

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
        $grant->setVerifyCredentialsCallback(function () {
            return 123;
        });

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    function testCompleteFlowNoScopes()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\ClientException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'username'  =>  'username',
            'password'  =>  'password'
        ];

        $server = new AuthorizationServer;
        $grant = new Password;

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new Client($server))->setId('testapp')
        );

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('create')->andreturn(123);
        $sessionStorage->shouldReceive('getScopes')->shouldReceive('getScopes')->andReturn([]);
        $sessionStorage->shouldReceive('associateScope');

        $accessTokenStorage = M::mock('League\OAuth2\Server\Storage\AccessTokenInterface');
        $accessTokenStorage->shouldReceive('setServer');
        $accessTokenStorage->shouldReceive('create');
        $accessTokenStorage->shouldReceive('getScopes')->andReturn([]);
        $accessTokenStorage->shouldReceive('associateScope');

        $scopeStorage = M::mock('League\OAuth2\Server\Storage\ScopeInterface');
        $scopeStorage->shouldReceive('setServer');

        $server->setClientStorage($clientStorage);
        $server->setScopeStorage($scopeStorage);
        $server->setSessionStorage($sessionStorage);
        $server->setAccessTokenStorage($accessTokenStorage);
        $server->requireScopeParam(true);
        $grant->setVerifyCredentialsCallback(function () {
            return 123;
        });

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    function testCompleteFlowInvalidCredentials()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\ClientException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'scope' =>  'foo',
            'username'  =>  'username',
            'password'  =>  'password'
        ];

        $server = new AuthorizationServer;
        $grant = new Password;

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
        $grant->setVerifyCredentialsCallback(function () {
            return false;
        });

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    function testCompleteFlow()
    {
        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'scope' =>  'foo',
            'username'  =>  'username',
            'password'  =>  'password'
        ];

        $server = new AuthorizationServer;
        $grant = new Password;

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
        $grant->setVerifyCredentialsCallback(function () {
            return 123;
        });

        $server->addGrantType($grant);
        $response = $server->issueAccessToken();

        $this->assertTrue(isset($response['access_token']));
        $this->assertTrue(isset($response['token_type']));
        $this->assertTrue(isset($response['expires_in']));
        $this->assertTrue(isset($response['expires']));
    }

    function testCompleteFlowRefreshToken()
    {
        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'scope' =>  'foo',
            'username'  =>  'username',
            'password'  =>  'password'
        ];

        $server = new AuthorizationServer;
        $grant = new Password;

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

        $refreshTokenStorage = M::mock('League\OAuth2\Server\Storage\RefreshTokenInterface');
        $refreshTokenStorage->shouldReceive('setServer');
        $refreshTokenStorage->shouldReceive('create');
        $refreshTokenStorage->shouldReceive('associateScope');

        $server->setClientStorage($clientStorage);
        $server->setScopeStorage($scopeStorage);
        $server->setSessionStorage($sessionStorage);
        $server->setAccessTokenStorage($accessTokenStorage);
        $server->setRefreshTokenStorage($refreshTokenStorage);

        $grant->setVerifyCredentialsCallback(function () {
            return 123;
        });

        $server->addGrantType($grant);
        $server->addGrantType(new RefreshToken);
        $response = $server->issueAccessToken();

        $this->assertTrue(isset($response['access_token']));
        $this->assertTrue(isset($response['refresh_token']));
        $this->assertTrue(isset($response['token_type']));
        $this->assertTrue(isset($response['expires_in']));
        $this->assertTrue(isset($response['expires']));
    }
}