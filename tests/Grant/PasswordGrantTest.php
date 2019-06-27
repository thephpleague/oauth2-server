<?php

namespace LeagueTests\Grant;

use DateInterval;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Grant\PasswordGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use LeagueTests\Stubs\UserEntity;
use PHPUnit\Framework\TestCase;
use Zend\Diactoros\ServerRequest;

class PasswordGrantTest extends TestCase
{
    const DEFAULT_SCOPE = 'basic';

    public function testGetIdentifier()
    {
        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new PasswordGrant($userRepositoryMock, $refreshTokenRepositoryMock);
        $this->assertEquals('password', $grant->getIdentifier());
    }

    public function testRespondToRequest()
    {
        $client = new ClientEntity();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new PasswordGrant($userRepositoryMock, $refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'username'      => 'foo',
            'password'      => 'bar',
        ]);

        $responseType = new StubResponseType();
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $responseType->getAccessToken());
        $this->assertInstanceOf(RefreshTokenEntityInterface::class, $responseType->getRefreshToken());
    }

    public function testRespondToRequestNullRefreshToken()
    {
        $client = new ClientEntity();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $scope = new ScopeEntity();
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(null);

        $grant = new PasswordGrant($userRepositoryMock, $refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'username'      => 'foo',
            'password'      => 'bar',
        ]);

        $responseType = new StubResponseType();
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new \DateInterval('PT5M'));

        $this->assertInstanceOf(AccessTokenEntityInterface::class, $responseType->getAccessToken());
        $this->assertNull($responseType->getRefreshToken());
    }

    public function testRespondToRequestMissingUsername()
    {
        $client = new ClientEntity();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new PasswordGrant($userRepositoryMock, $refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $serverRequest = (new ServerRequest())->withQueryParams([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
        ]);

        $responseType = new StubResponseType();

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testRespondToRequestMissingPassword()
    {
        $client = new ClientEntity();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new PasswordGrant($userRepositoryMock, $refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'username'      => 'alex',
        ]);

        $responseType = new StubResponseType();

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testRespondToRequestBadCredentials()
    {
        $client = new ClientEntity();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn(null);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new PasswordGrant($userRepositoryMock, $refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'client_secret' => 'bar',
            'username' => 'alex',
            'password' => 'whisky',
        ]);

        $responseType = new StubResponseType();

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(10);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }
}
