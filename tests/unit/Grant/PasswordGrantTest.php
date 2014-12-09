<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Entity\AccessTokenInterface;
use League\OAuth2\Server\Entity\ClientEntity;
use League\OAuth2\Server\Entity\FactoryInterface;
use League\OAuth2\Server\Entity\RefreshTokenInterface;
use League\OAuth2\Server\Entity\ScopeEntity;
use League\OAuth2\Server\Entity\SessionEntity;
use League\OAuth2\Server\Entity\SessionInterface;
use League\OAuth2\Server\Grant\PasswordGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use Mockery as M;
use PHPUnit_Framework_TestCase;

class PasswordGrantTest extends PHPUnit_Framework_TestCase
{
    /**
     * @var SessionInterface
     */
    private $session;
    
    /**
     * @var AccessTokenInterface
     */
    private $accessToken;
    
    /**
     * @var RefreshTokenInterface
     */
    private $refreshToken;
    
    /**
     * @var FactoryInterface
     */
    private $entityFactory;
    
    public function setUp()
    {
        $this->session = M::mock('League\OAuth2\Server\Entity\SessionInterface')
            ->shouldIgnoreMissing();
        $this->accessToken = M::mock('League\OAuth2\Server\Entity\AccessTokenInterface')
            ->shouldIgnoreMissing();
        $this->refreshToken = M::mock('League\OAuth2\Server\Entity\RefreshTokenInterface')
            ->shouldIgnoreMissing();
        $this->entityFactory = M::mock('League\OAuth2\Server\Entity\FactoryInterface');
        $this->entityFactory
            ->shouldReceive('buildSessionEntity')
            ->andReturn($this->session);
        $this->entityFactory
            ->shouldReceive('buildAccessTokenEntity')
            ->andReturn($this->accessToken);
        $this->entityFactory
            ->shouldReceive('buildRefreshTokenEntity')
            ->andReturn($this->refreshToken);
    }
    
    public function tearDown()
    {
        M::close();
    }
    
    public function testCompleteFlowMissingClientId()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST['grant_type'] = 'password';

        $server = new AuthorizationServer();
        $grant = new PasswordGrant($this->entityFactory);

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    public function testCompleteFlowMissingClientSecret()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
        ];

        $server = new AuthorizationServer();
        $grant = new PasswordGrant($this->entityFactory);

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    public function testCompleteFlowInvalidClient()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidClientException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
        ];

        $server = new AuthorizationServer();
        $grant = new PasswordGrant($this->entityFactory);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(null);

        $server->setClientStorage($clientStorage);

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    public function testNoUsername()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
        ];

        $server = new AuthorizationServer();
        $grant = new PasswordGrant($this->entityFactory);

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
        $server->issueAccessToken();
    }

    public function testNoPassword()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'username'  =>  'foo',
        ];

        $server = new AuthorizationServer();
        $grant = new PasswordGrant($this->entityFactory);

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
        $server->issueAccessToken();
    }

    public function testNoCallable()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\ServerErrorException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'username'  =>  'foo',
            'password'  =>  'foobar',
        ];

        $server = new AuthorizationServer();
        $grant = new PasswordGrant($this->entityFactory);

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
        $server->issueAccessToken();
    }

    public function testCompleteFlowInvalidScope()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidScopeException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'username'  =>  'foo',
            'password'  =>  'foobar',
            'scope' => 'foo',
        ];

        $server = new AuthorizationServer();
        $grant = new PasswordGrant($this->entityFactory);

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
        $grant->setVerifyCredentialsCallback(function () {
            return 123;
        });

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    public function testCompleteFlowNoScopes()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidRequestException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'username'  =>  'username',
            'password'  =>  'password',
        ];

        $server = new AuthorizationServer();
        $grant = new PasswordGrant($this->entityFactory);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
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

    public function testCompleteFlowInvalidCredentials()
    {
        $this->setExpectedException('League\OAuth2\Server\Exception\InvalidCredentialsException');

        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'scope' =>  'foo',
            'username'  =>  'username',
            'password'  =>  'password',
        ];

        $server = new AuthorizationServer();
        $grant = new PasswordGrant($this->entityFactory);

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
        $grant->setVerifyCredentialsCallback(function () {
            return false;
        });

        $server->addGrantType($grant);
        $server->issueAccessToken();
    }

    public function testCompleteFlow()
    {
        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'scope' =>  'foo',
            'username'  =>  'username',
            'password'  =>  'password',
        ];

        $server = new AuthorizationServer();
        $grant = new PasswordGrant($this->entityFactory);
        
        $this->session
            ->shouldReceive('getScopes')
            ->andReturn([
                (new ScopeEntity($server))->hydrate(['id' => 'foo']),
            ]);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('create')->andreturn(123);
        $sessionStorage->shouldReceive('getByAccessToken')->andReturn(
            (new SessionEntity($server))->setId('foobar')
        );
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
        $grant->setVerifyCredentialsCallback(function () {
            return 123;
        });

        $server->addGrantType($grant);
        $response = $server->issueAccessToken();

        $this->assertTrue(array_key_exists('access_token', $response));
        $this->assertTrue(array_key_exists('token_type', $response));
        $this->assertTrue(array_key_exists('expires_in', $response));
    }

    public function testCompleteFlowRefreshToken()
    {
        $_POST = [
            'grant_type' => 'password',
            'client_id' =>  'testapp',
            'client_secret' =>  'foobar',
            'scope' =>  'foo',
            'username'  =>  'username',
            'password'  =>  'password',
        ];

        $server = new AuthorizationServer();
        $grant = new PasswordGrant($this->entityFactory);

        $clientStorage = M::mock('League\OAuth2\Server\Storage\ClientInterface');
        $clientStorage->shouldReceive('setServer');
        $clientStorage->shouldReceive('get')->andReturn(
            (new ClientEntity($server))->hydrate(['id' => 'testapp'])
        );

        $this->session
            ->shouldReceive('getScopes')
            ->andReturn([
                (new ScopeEntity($server))->hydrate(['id' => 'foo']),
            ]);

        $sessionStorage = M::mock('League\OAuth2\Server\Storage\SessionInterface');
        $sessionStorage->shouldReceive('setServer');
        $sessionStorage->shouldReceive('create')->andreturn(123);
        
        $sessionStorage->shouldReceive('getByAccessToken')->andReturn(
            (new SessionEntity($server))->setId('foobar')
        );
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
        $server->addGrantType(new RefreshTokenGrant($this->entityFactory));
        $response = $server->issueAccessToken();

        $this->assertTrue(array_key_exists('access_token', $response));
        // $this->assertTrue(array_key_exists('refresh_token', $response));
        $this->assertTrue(array_key_exists('token_type', $response));
        $this->assertTrue(array_key_exists('expires_in', $response));
    }
}
