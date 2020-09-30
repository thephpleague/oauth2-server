<?php

namespace LeagueTests;

use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RevokeTokenHandler;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\CryptTraitStub;
use LeagueTests\Stubs\StubResponseType;
use PHPUnit\Framework\TestCase;

class RevokeTokenHandlerTest extends TestCase
{
    /**
     * @var CryptTraitStub
     */
    protected $cryptStub;

    public function setUp(): void
    {
        $this->cryptStub = new CryptTraitStub();
    }

    public function testRespondToRequestValidAccessTokenWithHint()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo.bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->expects($this->once())->method('revokeAccessToken');
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->expects($this->never())->method('revokeRefreshToken');

        $publicKey = new CryptKey('file://' . __DIR__ . '/Stubs/public.key');
        $handler = new RevokeTokenHandler($refreshTokenRepositoryMock, $publicKey);
        $handler->setClientRepository($clientRepositoryMock);
        $handler->setAccessTokenRepository($accessTokenRepositoryMock);
        $handler->setEncryptionKey($this->cryptStub->getKey());

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('test');
        $accessToken->setUserIdentifier(123);
        $accessToken->setExpiryDateTime((new \DateTimeImmutable())->sub(new \DateInterval('PT1H')));
        $accessToken->setClient($client);
        $accessToken->setPrivateKey(new CryptKey('file://' . __DIR__ . '/Stubs/private.key'));

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'       => 'foo',
                'client_secret'   => 'bar',
                'token'           => (string) $accessToken,
                'token_type_hint' => 'access_token',
            ]
        );

        $responseType = new StubResponseType();
        $handler->respondToRevokeTokenRequest($serverRequest, $responseType);
    }

    public function testRespondToRequestValidAccessTokenWithoutHint()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo.bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->expects($this->once())->method('revokeAccessToken');
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->expects($this->never())->method('revokeRefreshToken');

        $publicKey = new CryptKey('file://' . __DIR__ . '/Stubs/public.key');
        $handler = new RevokeTokenHandler($refreshTokenRepositoryMock, $publicKey);
        $handler->setClientRepository($clientRepositoryMock);
        $handler->setAccessTokenRepository($accessTokenRepositoryMock);
        $handler->setEncryptionKey($this->cryptStub->getKey());

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('test');
        $accessToken->setUserIdentifier(123);
        $accessToken->setExpiryDateTime((new \DateTimeImmutable())->sub(new \DateInterval('PT1H')));
        $accessToken->setClient($client);
        $accessToken->setPrivateKey(new CryptKey('file://' . __DIR__ . '/Stubs/private.key'));

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'       => 'foo',
                'client_secret'   => 'bar',
                'token'           => (string) $accessToken,
            ]
        );

        $responseType = new StubResponseType();
        $handler->respondToRevokeTokenRequest($serverRequest, $responseType);
    }

    public function testRespondToRequestValidAccessTokenButCannotRevokeAccessTokens()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo.bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->expects($this->never())->method('revokeAccessToken');
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->expects($this->never())->method('revokeRefreshToken');

        $publicKey = new CryptKey('file://' . __DIR__ . '/Stubs/public.key');
        $handler = new RevokeTokenHandler($refreshTokenRepositoryMock, $publicKey, false);
        $handler->setClientRepository($clientRepositoryMock);
        $handler->setAccessTokenRepository($accessTokenRepositoryMock);
        $handler->setEncryptionKey($this->cryptStub->getKey());

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('test');
        $accessToken->setUserIdentifier(123);
        $accessToken->setExpiryDateTime((new \DateTimeImmutable())->sub(new \DateInterval('PT1H')));
        $accessToken->setClient($client);
        $accessToken->setPrivateKey(new CryptKey('file://' . __DIR__ . '/Stubs/private.key'));

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'       => 'foo',
                'client_secret'   => 'bar',
                'token'           => (string) $accessToken,
                'token_type_hint' => 'access_token',
            ]
        );

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(2);

        $responseType = new StubResponseType();
        $handler->respondToRevokeTokenRequest($serverRequest, $responseType);
    }

    public function testRespondToRequestValidRefreshTokenWithHint()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo.bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->expects($this->once())->method('revokeAccessToken');
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->expects($this->once())->method('revokeRefreshToken');

        $publicKey = new CryptKey('file://' . __DIR__ . '/Stubs/public.key');
        $handler = new RevokeTokenHandler($refreshTokenRepositoryMock, $publicKey);
        $handler->setClientRepository($clientRepositoryMock);
        $handler->setAccessTokenRepository($accessTokenRepositoryMock);
        $handler->setEncryptionKey($this->cryptStub->getKey());

        $refreshToken = $this->cryptStub->doEncrypt(
            \json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => \time() + 3600,
                ]
            )
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'       => 'foo',
                'client_secret'   => 'bar',
                'token'           => $refreshToken,
                'token_type_hint' => 'refresh_token',
            ]
        );

        $responseType = new StubResponseType();
        $handler->respondToRevokeTokenRequest($serverRequest, $responseType);
    }

    public function testRespondToRequestValidRefreshTokenWithoutHint()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo.bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->expects($this->once())->method('revokeAccessToken');
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->expects($this->once())->method('revokeRefreshToken');

        $publicKey = new CryptKey('file://' . __DIR__ . '/Stubs/public.key');
        $handler = new RevokeTokenHandler($refreshTokenRepositoryMock, $publicKey);
        $handler->setClientRepository($clientRepositoryMock);
        $handler->setAccessTokenRepository($accessTokenRepositoryMock);
        $handler->setEncryptionKey($this->cryptStub->getKey());

        $refreshToken = $this->cryptStub->doEncrypt(
            \json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => \time() + 3600,
                ]
            )
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'       => 'foo',
                'client_secret'   => 'bar',
                'token'           => $refreshToken,
            ]
        );

        $responseType = new StubResponseType();
        $handler->respondToRevokeTokenRequest($serverRequest, $responseType);
    }

    public function testRespondToRequestValidRefreshTokenButCannotRevokeAccessTokens()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo.bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->expects($this->never())->method('revokeAccessToken');
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->expects($this->once())->method('revokeRefreshToken');

        $publicKey = new CryptKey('file://' . __DIR__ . '/Stubs/public.key');
        $handler = new RevokeTokenHandler($refreshTokenRepositoryMock, $publicKey, false);
        $handler->setClientRepository($clientRepositoryMock);
        $handler->setAccessTokenRepository($accessTokenRepositoryMock);
        $handler->setEncryptionKey($this->cryptStub->getKey());

        $refreshToken = $this->cryptStub->doEncrypt(
            \json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => \time() + 3600,
                ]
            )
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'       => 'foo',
                'client_secret'   => 'bar',
                'token'           => $refreshToken,
                'token_type_hint' => 'refresh_token',
            ]
        );

        $responseType = new StubResponseType();
        $handler->respondToRevokeTokenRequest($serverRequest, $responseType);
    }

    public function testRespondToRequestMissingToken()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo.bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->expects($this->never())->method('revokeAccessToken');
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->expects($this->never())->method('revokeRefreshToken');

        $publicKey = new CryptKey('file://' . __DIR__ . '/Stubs/public.key');
        $handler = new RevokeTokenHandler($refreshTokenRepositoryMock, $publicKey);
        $handler->setClientRepository($clientRepositoryMock);
        $handler->setAccessTokenRepository($accessTokenRepositoryMock);
        $handler->setEncryptionKey($this->cryptStub->getKey());

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'       => 'foo',
                'client_secret'   => 'bar',
            ]
        );

        $responseType = new StubResponseType();
        $handler->respondToRevokeTokenRequest($serverRequest, $responseType);
    }

    public function testRespondToRequestInvalidRefreshToken()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo.bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->expects($this->never())->method('revokeAccessToken');
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->expects($this->never())->method('revokeRefreshToken');

        $publicKey = new CryptKey('file://' . __DIR__ . '/Stubs/public.key');
        $handler = new RevokeTokenHandler($refreshTokenRepositoryMock, $publicKey);
        $handler->setClientRepository($clientRepositoryMock);
        $handler->setAccessTokenRepository($accessTokenRepositoryMock);
        $handler->setEncryptionKey($this->cryptStub->getKey());

        $refreshToken = 'foobar';

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'       => 'foo',
                'client_secret'   => 'bar',
                'token'           => $refreshToken,
                'token_type_hint' => 'refresh_token',
            ]
        );

        $responseType = new StubResponseType();
        $handler->respondToRevokeTokenRequest($serverRequest, $responseType);
    }

    public function testRespondToRequestClientMismatch()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo.bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->expects($this->never())->method('revokeAccessToken');
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->expects($this->never())->method('revokeRefreshToken');

        $publicKey = new CryptKey('file://' . __DIR__ . '/Stubs/public.key');
        $handler = new RevokeTokenHandler($refreshTokenRepositoryMock, $publicKey);
        $handler->setClientRepository($clientRepositoryMock);
        $handler->setAccessTokenRepository($accessTokenRepositoryMock);
        $handler->setEncryptionKey($this->cryptStub->getKey());

        $refreshToken = $this->cryptStub->doEncrypt(
            \json_encode(
                [
                    'client_id'        => 'bar',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => \time() + 3600,
                ]
            )
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'       => 'foo',
                'client_secret'   => 'bar',
                'token'           => $refreshToken,
                'token_type_hint' => 'refresh_token',
            ]
        );

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(4);

        $responseType = new StubResponseType();
        $handler->respondToRevokeTokenRequest($serverRequest, $responseType);
    }

    public function testRespondToRequestExpiredRefreshToken()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo.bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->expects($this->once())->method('revokeAccessToken');
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->expects($this->once())->method('revokeRefreshToken');

        $publicKey = new CryptKey('file://' . __DIR__ . '/Stubs/public.key');
        $handler = new RevokeTokenHandler($refreshTokenRepositoryMock, $publicKey);
        $handler->setClientRepository($clientRepositoryMock);
        $handler->setAccessTokenRepository($accessTokenRepositoryMock);
        $handler->setEncryptionKey($this->cryptStub->getKey());

        $refreshToken = $this->cryptStub->doEncrypt(
            \json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => \time() - 3600,
                ]
            )
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'       => 'foo',
                'client_secret'   => 'bar',
                'token'           => $refreshToken,
                'token_type_hint' => 'refresh_token',
            ]
        );

        $responseType = new StubResponseType();
        $handler->respondToRevokeTokenRequest($serverRequest, $responseType);
    }

    public function testRespondToRequestRevokedRefreshToken()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo.bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->expects($this->once())->method('revokeAccessToken');
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->expects($this->once())->method('revokeRefreshToken');

        $publicKey = new CryptKey('file://' . __DIR__ . '/Stubs/public.key');
        $handler = new RevokeTokenHandler($refreshTokenRepositoryMock, $publicKey);
        $handler->setClientRepository($clientRepositoryMock);
        $handler->setAccessTokenRepository($accessTokenRepositoryMock);
        $handler->setEncryptionKey($this->cryptStub->getKey());

        $refreshToken = $this->cryptStub->doEncrypt(
            \json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => \time() + 3600,
                ]
            )
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'       => 'foo',
                'client_secret'   => 'bar',
                'token'           => $refreshToken,
                'token_type_hint' => 'refresh_token',
            ]
        );

        $responseType = new StubResponseType();
        $handler->respondToRevokeTokenRequest($serverRequest, $responseType);
    }
}
