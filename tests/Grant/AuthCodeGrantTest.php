<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\AuthCodeEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\CryptTraitStub;
use LeagueTests\Stubs\RefreshTokenEntity;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use LeagueTests\Stubs\UserEntity;
use Zend\Diactoros\ServerRequest;

class AuthCodeGrantTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var CryptTraitStub
     */
    protected $cryptStub;

    public function setUp()
    {
        $this->cryptStub = new CryptTraitStub;
    }

    public function testGetIdentifier()
    {
        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );

        $this->assertEquals('authorization_code', $grant->getIdentifier());
    }

    public function testCanRespondToAuthorizationRequest()
    {
        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );

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

        $this->assertTrue($grant->canRespondToAuthorizationRequest($request));
    }

    public function testValidateAuthorizationRequest()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
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

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
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
                'redirect_uri'  => 'http://foo/bar',
            ]
        );

        $this->assertTrue($grant->validateAuthorizationRequest($request) instanceof AuthorizationRequest);
    }


    public function testValidateAuthorizationRequestCodeChallenge()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->enableCodeExchangeProof();
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
                'response_type'  => 'code',
                'client_id'      => 'foo',
                'redirect_uri'   => 'http://foo/bar',
                'code_challenge' => 'FOOBAR',
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

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
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

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
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

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
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

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
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
     * @expectedExceptionCode 3
     */
    public function testValidateAuthorizationRequestMissingCodeChallenge()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->enableCodeExchangeProof();
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
                'redirect_uri'  => 'http://foo/bar',
            ]
        );

        $grant->validateAuthorizationRequest($request);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 3
     */
    public function testValidateAuthorizationRequestInvalidCodeChallengeMethod()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->enableCodeExchangeProof();
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
                'response_type'         => 'code',
                'client_id'             => 'foo',
                'redirect_uri'          => 'http://foo/bar',
                'code_challenge'        => 'foobar',
                'code_challenge_method' => 'foo',
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

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );

        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));

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

        $authCodeRepository = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepository->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $grant = new AuthCodeGrant(
            $authCodeRepository,
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );

        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));

        $grant->completeAuthorizationRequest($authRequest);
    }

    public function testRespondToAccessTokenRequest()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    json_encode(
                        [
                            'auth_code_id' => uniqid(),
                            'expire_time'  => time() + 3600,
                            'client_id'    => 'foo',
                            'user_id'      => 123,
                            'scopes'       => ['foo'],
                            'redirect_uri' => 'http://foo/bar',
                        ]
                    )
                ),
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $this->assertTrue($response->getAccessToken() instanceof AccessTokenEntityInterface);
        $this->assertTrue($response->getRefreshToken() instanceof RefreshTokenEntityInterface);
    }

    public function testRespondToAccessTokenRequestCodeChallengePlain()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->enableCodeExchangeProof();
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
                'code_verifier' => 'foobar',
                'code'          => $this->cryptStub->doEncrypt(
                    json_encode(
                        [
                            'auth_code_id'          => uniqid(),
                            'expire_time'           => time() + 3600,
                            'client_id'             => 'foo',
                            'user_id'               => 123,
                            'scopes'                => ['foo'],
                            'redirect_uri'          => 'http://foo/bar',
                            'code_challenge'        => 'foobar',
                            'code_challenge_method' => 'plain',
                        ]
                    )
                ),
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $this->assertTrue($response->getAccessToken() instanceof AccessTokenEntityInterface);
        $this->assertTrue($response->getRefreshToken() instanceof RefreshTokenEntityInterface);
    }

    public function testRespondToAccessTokenRequestCodeChallengeS256()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->enableCodeExchangeProof();
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
                'code_verifier' => 'foobar',
                'code'          => $this->cryptStub->doEncrypt(
                    json_encode(
                        [
                            'auth_code_id'          => uniqid(),
                            'expire_time'           => time() + 3600,
                            'client_id'             => 'foo',
                            'user_id'               => 123,
                            'scopes'                => ['foo'],
                            'redirect_uri'          => 'http://foo/bar',
                            'code_challenge'        => urlencode(base64_encode(hash('sha256', 'foobar'))),
                            'code_challenge_method' => 'S256',
                        ]
                    )
                ),
            ]
        );

        /** @var StubResponseType $response */
        $response = $grant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $this->assertTrue($response->getAccessToken() instanceof AccessTokenEntityInterface);
        $this->assertTrue($response->getRefreshToken() instanceof RefreshTokenEntityInterface);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 3
     */
    public function testRespondToAccessTokenRequestMissingRedirectUri()
    {
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type' => 'authorization_code',
            ]
        );

        /* @var StubResponseType $response */
        $grant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 3
     */
    public function testRespondToAccessTokenRequestMissingCode()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'redirect_uri'  => 'http://foo/bar',
            ]
        );

        /* @var StubResponseType $response */
        $grant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
    }

    public function testRespondToAccessTokenRequestExpiredCode()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    json_encode(
                        [
                            'auth_code_id' => uniqid(),
                            'expire_time'  => time() - 3600,
                            'client_id'    => 'foo',
                            'user_id'      => 123,
                            'scopes'       => ['foo'],
                            'redirect_uri' => 'http://foo/bar',
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Authorization code has expired');
        }
    }

    public function testRespondToAccessTokenRequestRevokedCode()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $authCodeRepositoryMock = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepositoryMock->method('isAuthCodeRevoked')->willReturn(true);

        $grant = new AuthCodeGrant(
            $authCodeRepositoryMock,
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    json_encode(
                        [
                            'auth_code_id' => uniqid(),
                            'expire_time'  => time() + 3600,
                            'client_id'    => 'foo',
                            'user_id'      => 123,
                            'scopes'       => ['foo'],
                            'redirect_uri' => 'http://foo/bar',
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Authorization code has been revoked');
        }
    }

    public function testRespondToAccessTokenRequestClientMismatch()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    json_encode(
                        [
                            'auth_code_id' => uniqid(),
                            'expire_time'  => time() + 3600,
                            'client_id'    => 'bar',
                            'user_id'      => 123,
                            'scopes'       => ['foo'],
                            'redirect_uri' => 'http://foo/bar',
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Authorization code was not issued to this client');
        }
    }

    public function testRespondToAccessTokenRequestBadCodeEncryption()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => 'sdfsfsd',
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Cannot decrypt the authorization code');
        }
    }

    public function testRespondToAccessTokenRequestBadCodeVerifierPlain()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->enableCodeExchangeProof();
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
                'code_verifier' => 'nope',
                'code'          => $this->cryptStub->doEncrypt(
                    json_encode(
                        [
                            'auth_code_id'          => uniqid(),
                            'expire_time'           => time() + 3600,
                            'client_id'             => 'foo',
                            'user_id'               => 123,
                            'scopes'                => ['foo'],
                            'redirect_uri'          => 'http://foo/bar',
                            'code_challenge'        => 'foobar',
                            'code_challenge_method' => 'plain',
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Failed to verify `code_verifier`.');
        }
    }
    
    public function testRespondToAccessTokenRequestBadCodeVerifierS256()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->enableCodeExchangeProof();
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'    => 'authorization_code',
                'client_id'     => 'foo',
                'redirect_uri'  => 'http://foo/bar',
                'code_verifier' => 'nope',
                'code'          => $this->cryptStub->doEncrypt(
                    json_encode(
                        [
                            'auth_code_id'          => uniqid(),
                            'expire_time'           => time() + 3600,
                            'client_id'             => 'foo',
                            'user_id'               => 123,
                            'scopes'                => ['foo'],
                            'redirect_uri'          => 'http://foo/bar',
                            'code_challenge'        => 'foobar',
                            'code_challenge_method' => 'S256',
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Failed to verify `code_verifier`.');
        }
    }

    public function testRespondToAccessTokenRequestMissingCodeVerifier()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            new \DateInterval('PT10M')
        );
        $grant->enableCodeExchangeProof();
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setRefreshTokenRepository($refreshTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [],
            [],
            null,
            'POST',
            'php://input',
            [],
            [],
            [],
            [
                'grant_type'   => 'authorization_code',
                'client_id'    => 'foo',
                'redirect_uri' => 'http://foo/bar',
                'code'         => $this->cryptStub->doEncrypt(
                    json_encode(
                        [
                            'auth_code_id'          => uniqid(),
                            'expire_time'           => time() + 3600,
                            'client_id'             => 'foo',
                            'user_id'               => 123,
                            'scopes'                => ['foo'],
                            'redirect_uri'          => 'http://foo/bar',
                            'code_challenge'        => 'foobar',
                            'code_challenge_method' => 'plain',
                        ]
                    )
                ),
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToAccessTokenRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Check the `code_verifier` parameter');
        }
    }
}