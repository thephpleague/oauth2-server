<?php

namespace LeagueTests\Grant;

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
use Zend\Diactoros\ServerRequest;

class ImplicitGrantTest extends \PHPUnit_Framework_TestCase
{
    /**
     * CryptTrait stub
     */
    protected $cryptStub;

    public function setUp()
    {
        $this->cryptStub = new CryptTraitStub();
    }

    public function testGetIdentifier()
    {
        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $this->assertEquals('implicit', $grant->getIdentifier());
    }

    public function testCanRespondToAccessTokenRequest()
    {
        $grant = new ImplicitGrant(new \DateInterval('PT10M'));

        $this->assertFalse(
            $grant->canRespondToAccessTokenRequest(new ServerRequest())
        );
    }

    /**
     * @expectedException \LogicException
     */
    public function testRespondToAccessTokenRequest()
    {
        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->respondToAccessTokenRequest(
            new ServerRequest(),
            new StubResponseType(),
            new \DateInterval('PT10M')
        );
    }

    public function testCanRespondToAuthorizationRequest()
    {
        $grant = new ImplicitGrant(new \DateInterval('PT10M'));

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            $headers = [],
            $cookies = [],
            $queryParams = [
                'response_type' => 'token',
                'client_id'     => 'foo',
            ]
        );

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
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            $headers = [],
            $cookies = [],
            $queryParams = [
                'response_type' => 'code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
            ]
        );

        $this->assertTrue($grant->validateAuthorizationRequest($request) instanceof AuthorizationRequest);
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
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            $headers = [],
            $cookies = [],
            $queryParams = [
                'response_type' => 'code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
            ]
        );

        $this->assertTrue($grant->validateAuthorizationRequest($request) instanceof AuthorizationRequest);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 3
     */
    public function testValidateAuthorizationRequestMissingClientId()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            $headers = [],
            $cookies = [],
            $queryParams = [
                'response_type' => 'code',
            ]
        );

        $grant->validateAuthorizationRequest($request);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 4
     */
    public function testValidateAuthorizationRequestInvalidClientId()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn(null);

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            $headers = [],
            $cookies = [],
            $queryParams = [
                'response_type' => 'code',
                'client_id'     => 'foo',
            ]
        );

        $grant->validateAuthorizationRequest($request);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 4
     */
    public function testValidateAuthorizationRequestBadRedirectUriString()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            $headers = [],
            $cookies = [],
            $queryParams = [
                'response_type' => 'code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://bar',
            ]
        );

        $grant->validateAuthorizationRequest($request);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 4
     */
    public function testValidateAuthorizationRequestBadRedirectUriArray()
    {
        $client = new ClientEntity();
        $client->setRedirectUri(['http://foo/bar']);
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setClientRepository($clientRepositoryMock);

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            $headers = [],
            $cookies = [],
            $queryParams = [
                'response_type' => 'code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://bar',
            ]
        );

        $grant->validateAuthorizationRequest($request);
    }

    public function testCompleteAuthorizationRequest()
    {
        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient(new ClientEntity());
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $this->assertTrue($grant->completeAuthorizationRequest($authRequest) instanceof RedirectResponse);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 9
     */
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

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $grant->completeAuthorizationRequest($authRequest);
    }

    public function testAccessTokenRepositoryUniqueConstraintCheck()
    {
        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient(new ClientEntity());
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        /** @var AccessTokenRepositoryInterface|\PHPUnit_Framework_MockObject_MockObject $accessTokenRepositoryMock */
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->expects($this->at(0))->method('persistNewAccessToken')->willThrowException(UniqueTokenIdentifierConstraintViolationException::create());
        $accessTokenRepositoryMock->expects($this->at(1))->method('persistNewAccessToken')->willReturnSelf();

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $this->assertTrue($grant->completeAuthorizationRequest($authRequest) instanceof RedirectResponse);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 7
     */
    public function testAccessTokenRepositoryFailToPersist()
    {
        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient(new ClientEntity());
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        /** @var AccessTokenRepositoryInterface|\PHPUnit_Framework_MockObject_MockObject $accessTokenRepositoryMock */
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willThrowException(OAuthServerException::serverError('something bad happened'));

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $grant->completeAuthorizationRequest($authRequest);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException
     * @expectedExceptionCode 100
     */
    public function testAccessTokenRepositoryFailToPersistUniqueNoInfiniteLoop()
    {
        $authRequest = new AuthorizationRequest();
        $authRequest->setAuthorizationApproved(true);
        $authRequest->setClient(new ClientEntity());
        $authRequest->setGrantTypeId('authorization_code');
        $authRequest->setUser(new UserEntity());

        /** @var AccessTokenRepositoryInterface|\PHPUnit_Framework_MockObject_MockObject $accessTokenRepositoryMock */
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willThrowException(UniqueTokenIdentifierConstraintViolationException::create());

        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $grant->completeAuthorizationRequest($authRequest);
    }

    /**
     * @expectedException \LogicException
     */
    public function testSetRefreshTokenTTL()
    {
        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->setRefreshTokenTTL(new \DateInterval('PT10M'));
    }

    /**
     * @expectedException \LogicException
     */
    public function testSetRefreshTokenRepository()
    {
        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
    }

    /**
     * @expectedException \LogicException
     */
    public function testCompleteAuthorizationRequestNoUser()
    {
        $grant = new ImplicitGrant(new \DateInterval('PT10M'));
        $grant->completeAuthorizationRequest(new AuthorizationRequest());
    }
}
