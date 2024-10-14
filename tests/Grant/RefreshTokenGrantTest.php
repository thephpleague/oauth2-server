<?php

declare(strict_types=1);

namespace LeagueTests\Grant;

use DateInterval;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\CryptTraitStub;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use PHPUnit\Framework\TestCase;

use function json_encode;
use function time;

class RefreshTokenGrantTest extends TestCase
{
    protected CryptTraitStub $cryptStub;

    public function setUp(): void
    {
        $this->cryptStub = new CryptTraitStub();
    }

    public function testGetIdentifier(): void
    {
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        self::assertEquals('refresh_token', $grant->getIdentifier());
    }

    public function testRespondToRequest(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeEntity = new ScopeEntity();
        $scopeEntity->setIdentifier('foo');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturn([$scopeEntity]);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->expects(self::once())->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());
        $refreshTokenRepositoryMock->expects(self::once())->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->revokeRefreshTokens(true);

        $oldRefreshToken = json_encode(
            [
                'client_id'        => 'foo',
                'refresh_token_id' => 'zyxwvu',
                'access_token_id'  => 'abcdef',
                'scopes'           => ['foo'],
                'user_id'          => '123',
                'expire_time'      => time() + 3600,
            ]
        );

        if ($oldRefreshToken === false) {
            self::fail('json_encode failed');
        }

        $encryptedOldRefreshToken = $this->cryptStub->doEncrypt(
            $oldRefreshToken
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $encryptedOldRefreshToken,
            'scopes'        => ['foo'],
        ]);

        $responseType = new StubResponseType();
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));

        self::assertInstanceOf(RefreshTokenEntityInterface::class, $responseType->getRefreshToken());
    }

    public function testRespondToRequestNullRefreshToken(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeEntity = new ScopeEntity();
        $scopeEntity->setIdentifier('foo');

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturn([$scopeEntity]);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->expects(self::once())->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(null);
        $refreshTokenRepositoryMock->expects(self::never())->method('persistNewRefreshToken');

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $oldRefreshToken = json_encode(
            [
                'client_id'        => 'foo',
                'refresh_token_id' => 'zyxwvu',
                'access_token_id'  => 'abcdef',
                'scopes'           => ['foo'],
                'user_id'          => '123',
                'expire_time'      => time() + 3600,
            ]
        );

        if ($oldRefreshToken === false) {
            self::fail('json_encode failed');
        }

        $encryptedOldRefreshToken = $this->cryptStub->doEncrypt(
            $oldRefreshToken
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $encryptedOldRefreshToken,
            'scopes'        => ['foo'],
        ]);

        $responseType = new StubResponseType();
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));

        self::assertNull($responseType->getRefreshToken());
    }

    public function testRespondToReducedScopes(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $scope = new ScopeEntity();
        $scope->setIdentifier('foo');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturn([$scope]);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->revokeRefreshTokens(true);

        $oldRefreshToken = json_encode(
            [
                'client_id'        => 'foo',
                'refresh_token_id' => 'zyxwvu',
                'access_token_id'  => 'abcdef',
                'scopes'           => ['foo', 'bar'],
                'user_id'          => '123',
                'expire_time'      => time() + 3600,
            ]
        );

        if ($oldRefreshToken === false) {
            self::fail('json_encode failed');
        }

        $encryptedOldRefreshToken = $this->cryptStub->doEncrypt(
            $oldRefreshToken
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $encryptedOldRefreshToken,
            'scope'         => 'foo',
        ]);

        $responseType = new StubResponseType();
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));

        self::assertInstanceOf(RefreshTokenEntityInterface::class, $responseType->getRefreshToken());
    }

    public function testRespondToUnexpectedScope(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

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
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $oldRefreshToken = json_encode(
            [
                'client_id'        => 'foo',
                'refresh_token_id' => 'zyxwvu',
                'access_token_id'  => 'abcdef',
                'scopes'           => ['foo', 'bar'],
                'user_id'          => 123,
                'expire_time'      => time() + 3600,
            ]
        );

        if ($oldRefreshToken === false) {
            self::fail('json_encode failed');
        }

        $encryptedOldRefreshToken = $this->cryptStub->doEncrypt(
            $oldRefreshToken
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $encryptedOldRefreshToken,
            'scope'         => 'foobar',
        ]);

        $responseType = new StubResponseType();

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(5);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testRespondToRequestMissingOldToken(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
        ]);

        $responseType = new StubResponseType();

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testRespondToRequestInvalidOldToken(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $oldRefreshToken = 'foobar';

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $oldRefreshToken,
        ]);

        $responseType = new StubResponseType();

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(8);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testRespondToRequestClientMismatch(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $oldRefreshToken = json_encode(
            [
                'client_id'        => 'bar',
                'refresh_token_id' => 'zyxwvu',
                'access_token_id'  => 'abcdef',
                'scopes'           => ['foo'],
                'user_id'          => 123,
                'expire_time'      => time() + 3600,
            ]
        );

        if ($oldRefreshToken === false) {
            self::fail('json_encode failed');
        }

        $encryptedOldRefreshToken = $this->cryptStub->doEncrypt(
            $oldRefreshToken
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $encryptedOldRefreshToken,
        ]);

        $responseType = new StubResponseType();

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(8);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testRespondToRequestExpiredToken(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $oldRefreshToken = json_encode(
            [
                'client_id'        => 'foo',
                'refresh_token_id' => 'zyxwvu',
                'access_token_id'  => 'abcdef',
                'scopes'           => ['foo'],
                'user_id'          => 123,
                'expire_time'      => time() - 3600,
            ]
        );

        if ($oldRefreshToken === false) {
            self::fail('json_encode failed');
        }

        $encryptedOldRefreshToken = $this->cryptStub->doEncrypt(
            $oldRefreshToken
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $encryptedOldRefreshToken,
        ]);

        $responseType = new StubResponseType();

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(8);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testRespondToRequestRevokedToken(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->willReturn(true);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $oldRefreshToken = json_encode(
            [
                'client_id'        => 'foo',
                'refresh_token_id' => 'zyxwvu',
                'access_token_id'  => 'abcdef',
                'scopes'           => ['foo'],
                'user_id'          => 123,
                'expire_time'      => time() + 3600,
            ]
        );

        if ($oldRefreshToken === false) {
            self::fail('json_encode failed');
        }

        $encryptedOldRefreshToken = $this->cryptStub->doEncrypt(
            $oldRefreshToken
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $encryptedOldRefreshToken,
        ]);

        $responseType = new StubResponseType();

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(8);

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testRespondToRequestFinalizeScopes(): void
    {
        $client = new ClientEntity();

        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $fooScopeEntity = new ScopeEntity();
        $fooScopeEntity->setIdentifier('foo');

        $barScopeEntity = new ScopeEntity();
        $barScopeEntity->setIdentifier('bar');

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($fooScopeEntity, $barScopeEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));


        $scopes = [$fooScopeEntity, $barScopeEntity];
        $finalizedScopes = [$fooScopeEntity];

        $scopeRepositoryMock
            ->expects(self::once())
            ->method('finalizeScopes')
            ->with($scopes, $grant->getIdentifier(), $client)
            ->willReturn($finalizedScopes);

        $accessTokenRepositoryMock
            ->method('getNewToken')
            ->with($client, $finalizedScopes)
            ->willReturn(new AccessTokenEntity());

        $oldRefreshToken = json_encode(
            [
                'client_id'        => 'foo',
                'refresh_token_id' => 'zyxwvu',
                'access_token_id'  => 'abcdef',
                'scopes'           => ['foo', 'bar'],
                'user_id'          => '123',
                'expire_time'      => time() + 3600,
            ]
        );

        if ($oldRefreshToken === false) {
            self::fail('json_encode failed');
        }

        $encryptedOldRefreshToken = $this->cryptStub->doEncrypt(
            $oldRefreshToken
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $encryptedOldRefreshToken,
            'scope'         =>  'foo bar',
        ]);

        $responseType = new StubResponseType();

        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));
    }

    public function testRevokedRefreshToken(): void
    {
        $refreshTokenId = 'foo';

        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeEntity = new ScopeEntity();
        $scopeEntity->setIdentifier('foo');

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturn([$scopeEntity]);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->expects(self::once())->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('isRefreshTokenRevoked')
            ->will(self::onConsecutiveCalls(false, true));
        $refreshTokenRepositoryMock->expects(self::once())->method('revokeRefreshToken')->with(self::equalTo($refreshTokenId));

        $oldRefreshToken = json_encode(
            [
                'client_id'        => 'foo',
                'refresh_token_id' => $refreshTokenId,
                'access_token_id'  => 'abcdef',
                'scopes'           => ['foo'],
                'user_id'          => '123',
                'expire_time'      => time() + 3600,
            ]
        );

        if ($oldRefreshToken === false) {
            self::fail('json_encode failed');
        }

        $encryptedOldRefreshToken = $this->cryptStub->doEncrypt(
            $oldRefreshToken
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $encryptedOldRefreshToken,
            'scope'         => 'foo',
        ]);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->revokeRefreshTokens(true);
        $grant->respondToAccessTokenRequest($serverRequest, new StubResponseType(), new DateInterval('PT5M'));

        self::assertTrue($refreshTokenRepositoryMock->isRefreshTokenRevoked($refreshTokenId));
    }

    public function testUnrevokedRefreshToken(): void
    {
        $refreshTokenId = 'foo';

        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $scopeEntity = new ScopeEntity();
        $scopeEntity->setIdentifier('foo');

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturn([$scopeEntity]);

        $accessTokenEntity = new AccessTokenEntity();
        $accessTokenEntity->setClient($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn($accessTokenEntity);
        $accessTokenRepositoryMock->expects(self::once())->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());
        $refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->willReturn(false);
        $refreshTokenRepositoryMock->expects(self::never())->method('revokeRefreshToken');

        $oldRefreshToken = json_encode(
            [
                'client_id'        => 'foo',
                'refresh_token_id' => $refreshTokenId,
                'access_token_id'  => 'abcdef',
                'scopes'           => ['foo'],
                'user_id'          => '123',
                'expire_time'      => time() + 3600,
            ]
        );

        if ($oldRefreshToken === false) {
            self::fail('json_encode failed');
        }

        $encryptedOldRefreshToken = $this->cryptStub->doEncrypt(
            $oldRefreshToken
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $encryptedOldRefreshToken,
            'scope'         => 'foo',
        ]);

        $privateKey = new CryptKey('file://' . __DIR__ . '/../Stubs/private.key');

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setEncryptionKey($this->cryptStub->getKey());
        $grant->setPrivateKey($privateKey);
        $grant->revokeRefreshTokens(false);

        $responseType = new BearerTokenResponse();
        $responseType->setPrivateKey($privateKey);
        $responseType->setEncryptionKey($this->cryptStub->getKey());

        $response = $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'))
            ->generateHttpResponse(new Response());

        $json = json_decode((string) $response->getBody());

        self::assertFalse($refreshTokenRepositoryMock->isRefreshTokenRevoked($refreshTokenId));
        self::assertEquals('Bearer', $json->token_type);
        self::assertObjectHasProperty('expires_in', $json);
        self::assertObjectHasProperty('access_token', $json);
        self::assertObjectHasProperty('refresh_token', $json);
        self::assertNotSame($json->refresh_token, $encryptedOldRefreshToken);
    }
}
