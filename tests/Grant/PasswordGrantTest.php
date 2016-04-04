<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\Grant\PasswordGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\ResponseFactory;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\UserEntity;
use Zend\Diactoros\ServerRequest;

class PasswordGrantTest extends \PHPUnit_Framework_TestCase
{
    public function testGetIdentifier()
    {
        $userRepositoryMock = $this->getMock(UserRepositoryInterface::class);
        $refreshTokenRepositoryMock = $this->getMock(RefreshTokenRepositoryInterface::class);

        $grant = new PasswordGrant($userRepositoryMock, $refreshTokenRepositoryMock);
        $this->assertEquals('password', $grant->getIdentifier());
    }

    public function testRespondToRequest()
    {
        $client = new ClientEntity();
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new PasswordGrant($userRepositoryMock, $refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'username'      => 'foo',
                'password'      => 'bar',
            ]
        );

        $responseType = $grant->respondToRequest($serverRequest, new ResponseFactory(__DIR__ . '/Stubs/private.key', __DIR__ . '/Stubs/public.key'), new \DateInterval('PT5M'));
        $this->assertTrue($responseType instanceof BearerTokenResponse);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testRespondToRequestMissingUsername()
    {
        $client = new ClientEntity();
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new PasswordGrant($userRepositoryMock, $refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
            ]
        );

        $grant->respondToRequest($serverRequest, new ResponseFactory(__DIR__ . '/Stubs/private.key', __DIR__ . '/Stubs/public.key'), new \DateInterval('PT5M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testRespondToRequestMissingPassword()
    {
        $client = new ClientEntity();
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new PasswordGrant($userRepositoryMock, $refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'username'      => 'alex',
            ]
        );

        $grant->respondToRequest($serverRequest, new ResponseFactory(__DIR__ . '/Stubs/private.key', __DIR__ . '/Stubs/public.key'), new \DateInterval('PT5M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     */
    public function testRespondToRequestBadCredentials()
    {
        $client = new ClientEntity();
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn(null);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new PasswordGrant($userRepositoryMock, $refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'username'      => 'alex',
                'password'      => 'whisky',
            ]
        );

        $grant->respondToRequest($serverRequest, new ResponseFactory(__DIR__ . '/Stubs/private.key', __DIR__ . '/Stubs/public.key'), new \DateInterval('PT5M'));
    }
}
