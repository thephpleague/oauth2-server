<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\Entities\ClientEntity;
use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntity;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Utils\KeyCrypt;
use LeagueTests\Stubs\StubResponseType;
use Zend\Diactoros\ServerRequest;

class RefreshTokenGrantTest extends \PHPUnit_Framework_TestCase
{
    public function testGetIdentifier()
    {
        $refreshTokenRepositoryMock = $this->getMock(RefreshTokenRepositoryInterface::class);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $this->assertEquals('refresh_token', $grant->getIdentifier());
    }

    public function testRespondToRequest()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

        $oldRefreshToken = KeyCrypt::encrypt(
            json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => time() + 3600,
                ]
            ),
            'file://' . __DIR__ . '/../Utils/private.key'
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
            ]
        );

        $responseType = new StubResponseType();
        $grant->respondToRequest($serverRequest, $responseType, new \DateInterval('PT5M'));

        $this->assertTrue($responseType->getAccessToken() instanceof AccessTokenEntityInterface);
        $this->assertTrue($responseType->getRefreshToken() instanceof RefreshTokenEntityInterface);
    }

    public function testRespondToReducedScopes()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $scope = new ScopeEntity();
        $scope->setIdentifier('foo');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

        $oldRefreshToken = KeyCrypt::encrypt(
            json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo', 'bar'],
                    'user_id'          => 123,
                    'expire_time'      => time() + 3600,
                ]
            ),
            'file://' . __DIR__ . '/../Utils/private.key'
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
                'scope'         => 'foo',
            ]
        );

        $responseType = new StubResponseType();
        $grant->respondToRequest($serverRequest, $responseType, new \DateInterval('PT5M'));

        $this->assertTrue($responseType->getAccessToken() instanceof AccessTokenEntityInterface);
        $this->assertTrue($responseType->getRefreshToken() instanceof RefreshTokenEntityInterface);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 5
     */
    public function testRespondToUnexpectedScope()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $scope = new ScopeEntity();
        $scope->setIdentifier('foobar');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

        $oldRefreshToken = KeyCrypt::encrypt(
            json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo', 'bar'],
                    'user_id'          => 123,
                    'expire_time'      => time() + 3600,
                ]
            ),
            'file://' . __DIR__ . '/../Utils/private.key'
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
                'scope'         => 'foobar',
            ]
        );

        $responseType = new StubResponseType();
        $grant->respondToRequest($serverRequest, $responseType, new \DateInterval('PT5M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 3
     */
    public function testRespondToRequestMissingOldToken()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
            ]
        );

        $responseType = new StubResponseType();
        $grant->respondToRequest($serverRequest, $responseType, new \DateInterval('PT5M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 8
     */
    public function testRespondToRequestInvalidOldToken()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

        $oldRefreshToken = 'foobar';

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
            ]
        );

        $responseType = new StubResponseType();
        $grant->respondToRequest($serverRequest, $responseType, new \DateInterval('PT5M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 8
     */
    public function testRespondToRequestClientMismatch()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();


        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

        $oldRefreshToken = KeyCrypt::encrypt(
            json_encode(
                [
                    'client_id'        => 'bar',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => time() + 3600,
                ]
            ),
            'file://' . __DIR__ . '/../Utils/private.key'
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
            ]
        );

        $responseType = new StubResponseType();
        $grant->respondToRequest($serverRequest, $responseType, new \DateInterval('PT5M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 8
     */
    public function testRespondToRequestExpiredToken()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

        $oldRefreshToken = KeyCrypt::encrypt(
            json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => time() - 3600,
                ]
            ),
            'file://' . __DIR__ . '/../Utils/private.key'
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
            ]
        );

        $responseType = new StubResponseType();
        $grant->respondToRequest($serverRequest, $responseType, new \DateInterval('PT5M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 8
     */
    public function testRespondToRequestRevokedToken()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->willReturn(true);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

        $oldRefreshToken = KeyCrypt::encrypt(
            json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => time() + 3600,
                ]
            ),
            'file://' . __DIR__ . '/../Utils/private.key'
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
            ]
        );

        $responseType = new StubResponseType();
        $grant->respondToRequest($serverRequest, $responseType, new \DateInterval('PT5M'));
    }
}
