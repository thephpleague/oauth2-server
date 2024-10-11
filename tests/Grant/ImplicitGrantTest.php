<?php

declare(strict_types=1);

namespace LeagueTests\Grant;

use DateInterval;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException;
use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\CryptTraitStub;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use LeagueTests\Stubs\UserEntity;
use LogicException;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class ImplicitGrantTest extends TestCase
{
    private const DEFAULT_SCOPE = 'basic';
    private const REDIRECT_URI = 'https://foo/bar';

    protected CryptTraitStub $cryptStub;

    public function setUp(): void
    {
        $this->cryptStub = new CryptTraitStub();
    }

    public function testGetIdentifier(): void
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        self::assertEquals('implicit', $grant->getIdentifier());
    }

    public function testCanRespondToAccessTokenRequest(): void
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));

        self::assertFalse(
            $grant->canRespondToAccessTokenRequest(new ServerRequest('', ''))
        );
    }

    public function testRespondToAccessTokenRequest(): void
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));

        $this->expectException(LogicException::class);

        $grant->respondToAccessTokenRequest(
            new ServerRequest('', ''),
            new StubResponseType(),
            new DateInterval('PT10M')
        );
    }

    public function testCanRespondToAuthorizationRequest(): void
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));

        $request = (new ServerRequest('', ''))->withQueryParams([
            'response_type' => 'token',
            'client_id'     => 'foo',
        ]);

        self::assertTrue($grant->canRespondToAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequest(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest('', ''))->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
            'redirect_uri'  => self::REDIRECT_URI,
        ]);

        self::assertInstanceOf(AuthorizationRequest::class, $grant->validateAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequestRedirectUriArray(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri([self::REDIRECT_URI]);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest('', ''))->withQueryParams([
            'response_type' => 'code',
            'client_id' => 'foo',
            'redirect_uri' => self::REDIRECT_URI,
        ]);

        self::assertInstanceOf(AuthorizationRequest::class, $grant->validateAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequestMissingClientId(): void
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest('', ''))->withQueryParams(['response_type' => 'code']);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestInvalidClientId(): void
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn(null);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest('', ''))->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
        ]);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(4);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestBadRedirectUriString(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri(self::REDIRECT_URI);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest('', ''))->withQueryParams([
            'response_type' => 'code',
            'client_id' => 'foo',
            'redirect_uri' => 'http://bar',
        ]);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(4);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestBadRedirectUriArray(): void
    {
        $client = new ClientEntity();
        $client->setRedirectUri([self::REDIRECT_URI]);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest('', ''))->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
            'redirect_uri'  => 'http://bar',
        ]);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(4);

        $grant->validateAuthorizationRequest($request);
    }

    public function testCompleteAuthorizationRequest(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('identifier');
        $client->setRedirectUri('https://foo/bar');

        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        $accessToken = new AccessTokenEntity();
        $accessToken->setClient($client);
        $accessToken->setUserIdentifier('userId');

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn($accessToken);
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        self::assertInstanceOf(RedirectResponse::class, $grant->completeAuthorizationRequest($authRequest));
    }

    public function testCompleteAuthorizationRequestDenied(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('clientId');
        $client->setRedirectUri('https://foo/bar');

        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(false);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(9);

        $grant->completeAuthorizationRequest($authRequest);
    }

    public function testAccessTokenRepositoryUniqueConstraintCheck(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('clientId');
        $client->setRedirectUri('https://foo/bar');

        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        $accessToken = new AccessTokenEntity();
        $accessToken->setClient($client);
        $accessToken->setUserIdentifier('userId');

        /** @var AccessTokenRepositoryInterface|MockObject $accessTokenRepositoryMock */
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn($accessToken);

        $accessTokenRepositoryMock
            ->expects(self::exactly(2))
            ->method('persistNewAccessToken')
            ->willReturnCallback(function (): void {
                static $count = 0;

                if (1 === ++$count) {
                    throw UniqueTokenIdentifierConstraintViolationException::create();
                }
            });

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        self::assertInstanceOf(RedirectResponse::class, $grant->completeAuthorizationRequest($authRequest));
    }

    public function testAccessTokenRepositoryFailToPersist(): void
    {
        $client = new ClientEntity();

        $client->setRedirectUri('https://foo/bar');

        $authRequest = new AuthorizationRequest();

        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        /** @var AccessTokenRepositoryInterface|MockObject $accessTokenRepositoryMock */
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willThrowException(OAuthServerException::serverError('something bad happened'));

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $this->expectException(OAuthServerException::class);
        $this->expectExceptionCode(7);

        $grant->completeAuthorizationRequest($authRequest);
    }

    public function testAccessTokenRepositoryFailToPersistUniqueNoInfiniteLoop(): void
    {
        $client = new ClientEntity();

        $client->setRedirectUri('https://foo/bar');

        $authRequest = new AuthorizationRequest();

        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        /** @var AccessTokenRepositoryInterface|MockObject $accessTokenRepositoryMock */
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willThrowException(UniqueTokenIdentifierConstraintViolationException::create());

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $this->expectException(UniqueTokenIdentifierConstraintViolationException::class);
        $this->expectExceptionCode(100);

        $grant->completeAuthorizationRequest($authRequest);
    }

    public function testSetRefreshTokenTTL(): void
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));

        $this->expectException(LogicException::class);

        $grant->setRefreshTokenTTL(new DateInterval('PT10M'));
    }

    public function testSetRefreshTokenRepository(): void
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $this->expectException(LogicException::class);

        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
    }

    public function testCompleteAuthorizationRequestNoUser(): void
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));

        $this->expectException(LogicException::class);

        $grant->completeAuthorizationRequest(new AuthorizationRequest());
    }
}
