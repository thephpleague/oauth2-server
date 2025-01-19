<?php

declare(strict_types=1);

namespace LeagueTests\Grant;

use DateInterval;
use DateTimeImmutable;
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
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestRefreshTokenEvent;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use LeagueTests\Stubs\UserEntity;
use PHPUnit\Framework\TestCase;

use function json_encode;
use function time;

class RefreshTokenGrantTest extends TestCase
{
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

        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef1');
        $ace->setClient($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn($ace);
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef1');
        $ace->setClient($client);
        $accessTokenRepositoryMock->method('getAccessTokenEntity')->willReturn($ace);
        $accessTokenRepositoryMock->expects(self::once())->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $rte = new RefreshTokenEntity();
        $rte->setClient($client);
        $rte->setIdentifier('zyxwvu');
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef2');
        $ace->setClient($client);
        $rte->setAccessToken($ace);
        $rte->setScopes(['foo']);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $rte->setUser($user);
        $rte->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));

        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());
        $refreshTokenRepositoryMock->method('getRefreshTokenEntity')->willReturn($rte);
        $refreshTokenRepositoryMock->expects(self::once())->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->revokeRefreshTokens(true);

        $accessTokenEventEmitted = false;
        $refreshTokenEventEmitted = false;

        $grant->getListenerRegistry()->subscribeTo(
            RequestEvent::ACCESS_TOKEN_ISSUED,
            function ($event) use (&$accessTokenEventEmitted): void {
                self::assertInstanceOf(RequestAccessTokenEvent::class, $event);

                $accessTokenEventEmitted = true;
            }
        );

        $grant->getListenerRegistry()->subscribeTo(
            RequestEvent::REFRESH_TOKEN_ISSUED,
            function ($event) use (&$refreshTokenEventEmitted): void {
                self::assertInstanceOf(RequestRefreshTokenEvent::class, $event);

                $refreshTokenEventEmitted = true;
            }
        );

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => 'zyxwvu',
            'scopes'        => ['foo'],
        ]);

        $responseType = new StubResponseType();
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));

        self::assertInstanceOf(RefreshTokenEntityInterface::class, $responseType->getRefreshToken());

        if (!$accessTokenEventEmitted) {
            self::fail('Access token issued event is not emitted.');
        }

        if (!$refreshTokenEventEmitted) {
            self::fail('Refresh token issued event is not emitted.');
        }
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

        $accessToken = new AccessTokenEntity();
        $accessToken->setClient($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn($accessToken);
        $accessTokenRepositoryMock->expects(self::once())->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $rte = new RefreshTokenEntity();
        $rte->setClient($client);
        $rte->setIdentifier('zyxwvu');
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $rte->setAccessToken($ace);
        $rte->setScopes(['foo']);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $rte->setUser($user);
        $rte->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));

        $refreshTokenRepositoryMock->method('getRefreshTokenEntity')->willReturn($rte);
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(null);
        $refreshTokenRepositoryMock->expects(self::never())->method('persistNewRefreshToken');

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => 'zyxwvu',
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
        $accessToken = new AccessTokenEntity();
        $accessToken->setClient($client);
        $accessTokenRepositoryMock->method('getNewToken')->willReturn($accessToken);
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $accessTokenRepositoryMock->method('getAccessTokenEntity')->willReturn($ace);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $rte = new RefreshTokenEntity();
        $rte->setClient($client);
        $rte->setIdentifier('zyxwvu');
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $rte->setAccessToken($ace);
        $rte->setScopes(['foo']);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $rte->setUser($user);
        $rte->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));

        $refreshTokenRepositoryMock->method('getRefreshTokenEntity')->willReturn($rte);

        $scope = new ScopeEntity();
        $scope->setIdentifier('foo');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);
        $scopeRepositoryMock->method('finalizeScopes')->willReturn([$scope]);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->revokeRefreshTokens(true);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => 'zyxwvu',
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
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $accessTokenRepositoryMock->method('getAccessTokenEntity')->willReturn($ace);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $rte = new RefreshTokenEntity();
        $rte->setClient($client);
        $rte->setIdentifier('zyxwvu');
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $rte->setAccessToken($ace);
        $rte->setScopes(['foo', 'bar']);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $rte->setUser($user);
        $rte->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));

        $refreshTokenRepositoryMock->method('getRefreshTokenEntity')->willReturn($rte);


        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope1, $scope2, $scope3);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => 'zyxwvu',
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

    public function testRespondToRequestRefreshTokenNotSet(): void
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

        $client2 = new ClientEntity();
        $client2->setIdentifier('bar');
        $client2->setRedirectUri('http://foo/bar');

        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client, $client2);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $accessTokenRepositoryMock->method('getAccessTokenEntity')->willReturn($ace);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $scope1 = new ScopeEntity();
        $scope1->setIdentifier('foo');

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope1);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => 'zyxwvu',
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
        $clientRepositoryMock->method('getClientEntity')->willReturn($client, $client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $accessTokenRepositoryMock->method('getAccessTokenEntity')->willReturn($ace);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $scope1 = new ScopeEntity();
        $scope1->setIdentifier('foo');

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope1);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => 'zyxwvu',
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
        $clientRepositoryMock->method('getClientEntity')->willReturn($client, $client);
        $clientRepositoryMock->method('validateClient')->willReturn(true);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $accessTokenRepositoryMock->method('getAccessTokenEntity')->willReturn($ace);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->willReturn(true);
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $scope1 = new ScopeEntity();
        $scope1->setIdentifier('foo');

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope1);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => 'zyxwvu',
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
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($fooScopeEntity, $barScopeEntity, $fooScopeEntity, $barScopeEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $accessTokenRepositoryMock->method('getAccessTokenEntity')->willReturn($ace);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $rte = new RefreshTokenEntity();
        $rte->setClient($client);
        $rte->setIdentifier('zyxwvu');
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $rte->setAccessToken($ace);
        $rte->setScopes(['foo', 'bar']);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $rte->setUser($user);
        $rte->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));

        $refreshTokenRepositoryMock->method('getRefreshTokenEntity')->willReturn($rte);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);


        $scopes = [$fooScopeEntity, $barScopeEntity];
        $finalizedScopes = [$fooScopeEntity];

        $scopeRepositoryMock
            ->expects(self::once())
            ->method('finalizeScopes')
            ->with($scopes, $grant->getIdentifier(), $client)
            ->willReturn($finalizedScopes);

        $accessToken = new AccessTokenEntity();
        $accessToken->setClient($client);
        $accessTokenRepositoryMock
            ->method('getNewToken')
            ->with($client, $finalizedScopes)
            ->willReturn($accessToken);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => 'zyxwvu',
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
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity, $scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturn([$scopeEntity]);

        $accessToken = new AccessTokenEntity();
        $accessToken->setClient($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn($accessToken);
        $accessTokenRepositoryMock->expects(self::once())->method('persistNewAccessToken')->willReturnSelf();
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $accessTokenRepositoryMock->method('getAccessTokenEntity')->willReturn($ace);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('isRefreshTokenRevoked')
            ->will(self::onConsecutiveCalls(false, true));
        $refreshTokenRepositoryMock->expects(self::once())->method('revokeRefreshToken')->with(self::equalTo($refreshTokenId));
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $rte = new RefreshTokenEntity();
        $rte->setClient($client);
        $rte->setIdentifier($refreshTokenId);
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $rte->setAccessToken($ace);
        $rte->setScopes(['foo']);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $rte->setUser($user);
        $rte->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));

        $refreshTokenRepositoryMock->method('getRefreshTokenEntity')->willReturn($rte);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $refreshTokenId,
            'scope'         => 'foo',
        ]);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
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
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $accessTokenRepositoryMock->method('getAccessTokenEntity')->willReturn($ace);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());
        $refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->willReturn(false);
        $refreshTokenRepositoryMock->expects(self::never())->method('revokeRefreshToken');

        $rte = new RefreshTokenEntity();
        $rte->setClient($client);
        $rte->setIdentifier('zyxwvu');
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $rte->setAccessToken($ace);
        $rte->setScopes(['foo']);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $rte->setUser($user);
        $rte->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));

        $refreshTokenRepositoryMock->method('getRefreshTokenEntity')->willReturn($rte);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => $refreshTokenId,
            'scope'         => 'foo',
        ]);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->revokeRefreshTokens(false);

        $responseType = new BearerTokenResponse();

        $response = $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'))
            ->generateHttpResponse(new Response());

        $json = json_decode((string) $response->getBody());

        self::assertFalse($refreshTokenRepositoryMock->isRefreshTokenRevoked($refreshTokenId));
        self::assertEquals('Bearer', $json->token_type);
        self::assertObjectHasProperty('expires_in', $json);
        self::assertObjectHasProperty('access_token', $json);
        self::assertObjectHasProperty('refresh_token', $json);
        self::assertNotSame($json->refresh_token, $refreshTokenId);
    }

    public function testRespondToRequestWithIntUserId(): void
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
        $accessTokenEntity = new AccessTokenEntity();
        $accessTokenEntity->setClient($client);
        $accessTokenRepositoryMock->method('getNewToken')->willReturn($accessTokenEntity);
        $accessTokenRepositoryMock->expects(self::once())->method('persistNewAccessToken')->willReturnSelf();
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $accessTokenRepositoryMock->method('getAccessTokenEntity')->willReturn($ace);

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());
        $refreshTokenRepositoryMock->expects(self::once())->method('persistNewRefreshToken')->willReturnSelf();

        $rte = new RefreshTokenEntity();
        $rte->setClient($client);
        $rte->setIdentifier('zyxwvu');
        $ace = new AccessTokenEntity();
        $ace->setIdentifier('abcdef');
        $rte->setAccessToken($ace);
        $rte->setScopes(['foo']);
        $user = new UserEntity();
        $user->setIdentifier('123');
        $rte->setUser($user);
        $rte->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));

        $refreshTokenRepositoryMock->method('getRefreshTokenEntity')->willReturn($rte);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->revokeRefreshTokens(true);

        $serverRequest = (new ServerRequest())->withParsedBody([
            'client_id'     => 'foo',
            'client_secret' => 'bar',
            'refresh_token' => 'zyxwvu',
            'scopes'        => ['foo'],
        ]);

        $responseType = new StubResponseType();
        $grant->respondToAccessTokenRequest($serverRequest, $responseType, new DateInterval('PT5M'));

        self::assertInstanceOf(RefreshTokenEntityInterface::class, $responseType->getRefreshToken());
    }
}
