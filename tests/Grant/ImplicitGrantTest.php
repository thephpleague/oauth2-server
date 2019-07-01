<?php

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
use PHPUnit\Framework\TestCase;
use Zend\Diactoros\ServerRequest;

class ImplicitGrantTest extends TestCase
{
    const DEFAULT_SCOPE = 'basic';

    /**
     * CryptTrait stub
     */
    protected $cryptStub;

    public function setUp(): void
    {
        $this->cryptStub = new CryptTraitStub();
    }

    public function testGetIdentifier()
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $this->assertEquals('implicit', $grant->getIdentifier());
    }

    public function testCanRespondToAccessTokenRequest()
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));

        $this->assertFalse(
            $grant->canRespondToAccessTokenRequest(new ServerRequest())
        );
    }

    public function testRespondToAccessTokenRequest()
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));

        $this->expectException(\LogicException::class);

        $grant->respondToAccessTokenRequest(
            new ServerRequest(),
            new StubResponseType(),
            new DateInterval('PT10M')
        );
    }

    public function testCanRespondToAuthorizationRequest()
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'token',
            'client_id'     => 'foo',
        ]);

        $this->assertTrue($grant->canRespondToAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequest()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
            'redirect_uri'  => 'http://foo/bar',
        ]);

        $this->assertInstanceOf(AuthorizationRequest::class, $grant->validateAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequestRedirectUriArray()
    {
        $client = new ClientEntity();
        $client->setRedirectUri(['http://foo/bar']);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setDefaultScope(self::DEFAULT_SCOPE);

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
            'client_id' => 'foo',
            'redirect_uri' => 'http://foo/bar',
        ]);

        $this->assertInstanceOf(AuthorizationRequest::class, $grant->validateAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequestMissingClientId()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest())->withQueryParams(['response_type' => 'code']);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(3);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestInvalidClientId()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn(null);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(4);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestBadRedirectUriString()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
            'client_id' => 'foo',
            'redirect_uri' => 'http://bar',
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(4);

        $grant->validateAuthorizationRequest($request);
    }

    public function testValidateAuthorizationRequestBadRedirectUriArray()
    {
        $client = new ClientEntity();
        $client->setRedirectUri(['http://foo/bar']);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new ImplicitGrant(new DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);

        $request = (new ServerRequest())->withQueryParams([
            'response_type' => 'code',
            'client_id'     => 'foo',
            'redirect_uri'  => 'http://bar',
        ]);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(4);

        $grant->validateAuthorizationRequest($request);
    }

    public function testCompleteAuthorizationRequest()
    {
        $client = new ClientEntity();
        $client->setIdentifier('identifier');

        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        $accessToken = new AccessTokenEntity();
        $accessToken->setClient($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn($accessToken);
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $this->assertInstanceOf(RedirectResponse::class, $grant->completeAuthorizationRequest($authRequest));
    }

    public function testCompleteAuthorizationRequestDenied()
    {
        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(false);
        $authRequest->setClient(new ClientEntity());
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(9);

        $grant->completeAuthorizationRequest($authRequest);
    }

    public function testAccessTokenRepositoryUniqueConstraintCheck()
    {
        $client = new ClientEntity();
        $client->setIdentifier('identifier');

        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient($client);
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        $accessToken = new AccessTokenEntity();
        $accessToken->setClient($client);

        /** @var AccessTokenRepositoryInterface|\PHPUnit\Framework\MockObject\MockObject $accessTokenRepositoryMock */
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn($accessToken);
        $accessTokenRepositoryMock->expects($this->at(0))->method('persistNewAccessToken')->willThrowException(UniqueTokenIdentifierConstraintViolationException::create());
        $accessTokenRepositoryMock->expects($this->at(1))->method('persistNewAccessToken')->willReturnSelf();

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $this->assertInstanceOf(RedirectResponse::class, $grant->completeAuthorizationRequest($authRequest));
    }

    public function testAccessTokenRepositoryFailToPersist()
    {
        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient(new ClientEntity());
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        /** @var AccessTokenRepositoryInterface|\PHPUnit\Framework\MockObject\MockObject $accessTokenRepositoryMock */
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willThrowException(OAuthServerException::serverError('something bad happened'));

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $this->expectException(\League\OAuth2\Server\Exception\OAuthServerException::class);
        $this->expectExceptionCode(7);

        $grant->completeAuthorizationRequest($authRequest);
    }

    public function testAccessTokenRepositoryFailToPersistUniqueNoInfiniteLoop()
    {
        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient(new ClientEntity());
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        /** @var AccessTokenRepositoryInterface|\PHPUnit\Framework\MockObject\MockObject $accessTokenRepositoryMock */
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willThrowException(UniqueTokenIdentifierConstraintViolationException::create());

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $this->expectException(\League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException::class);
        $this->expectExceptionCode(100);

        $grant->completeAuthorizationRequest($authRequest);
    }

    public function testSetRefreshTokenTTL()
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));

        $this->expectException(\LogicException::class);

        $grant->setRefreshTokenTTL(new DateInterval('PT10M'));
    }

    public function testSetRefreshTokenRepository()
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $this->expectException(\LogicException::class);

        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
    }

    public function testCompleteAuthorizationRequestNoUser()
    {
        $grant = new ImplicitGrant(new DateInterval('PT10M'));

        $this->expectException(\LogicException::class);

        $grant->completeAuthorizationRequest(new AuthorizationRequest());
    }
}
