<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\Interfaces\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Interfaces\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntity;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\HtmlResponse;
use League\OAuth2\Server\ResponseTypes\RedirectResponse;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\CryptTraitStub;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use LeagueTests\Stubs\UserEntity;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

class AuthCodeGrantTest extends \PHPUnit_Framework_TestCase
{
    /**
     * CryptTrait stub
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
            $this->getMock(UserRepositoryInterface::class),
            new \DateInterval('PT10M')
        );

        $this->assertEquals('authorization_code', $grant->getIdentifier());
    }

    public function testCanRespondToRequest()
    {
        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $this->getMock(UserRepositoryInterface::class),
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

        $this->assertTrue($grant->canRespondToRequest($request));
    }

    public function testRespondToAuthorizationRequest()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $authCodeRepoMock = $this->getMock(AuthCodeRepositoryInterface::class);
        $authCodeRepoMock->expects($this->once())->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $grant = new AuthCodeGrant(
            $authCodeRepoMock,
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [
                'HTTP_HOST'   => 'auth-server.tld',
                'REQUEST_URI' => '/authorize',
            ],
            [],
            null,
            'POST',
            'php://input',
            [],
            [
                'oauth_authorize_request' => $this->cryptStub->doEncrypt(json_encode(['user_id' => 123])),
            ],
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
                'state'         => 'foobar',
            ],
            [
                'username' => 'alex',
                'password' => 'whisky',
                'action'   => 'approve',
            ]
        );

        $response = $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $this->assertTrue($response instanceof RedirectResponse);

        $response = $response->generateHttpResponse(new Response);
        $this->assertTrue(strstr($response->getHeader('location')[0], 'http://foo/bar') !== false);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 9
     */
    public function testRespondToAuthorizationRequestUserDenied()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [
                'HTTP_HOST'   => 'auth-server.tld',
                'REQUEST_URI' => '/authorize',
            ],
            [],
            null,
            'POST',
            'php://input',
            [],
            [
                'oauth_authorize_request' => $this->cryptStub->doEncrypt(json_encode(['user_id' => 123])),
            ],
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
                'state'         => 'foobar',
            ],
            [
                'username' => 'alex',
                'password' => 'whisky',
                'action'   => 'denied',
            ]
        );

        $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 3
     */
    public function testRespondToAuthorizationRequestMissingClientId()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [
                'HTTP_HOST'   => 'auth-server.tld',
                'REQUEST_URI' => '/authorize',
            ],
            [],
            null,
            'POST',
            'php://input',
            [],
            [
                'oauth_authorize_request' => $this->cryptStub->doEncrypt(json_encode(['user_id' => 123])),
            ],
            [
                'response_type' => 'code',
            ],
            [
                'username' => 'alex',
                'password' => 'whisky',
                'action'   => 'approve',
            ]
        );

        $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
    }

    public function testRespondToAuthorizationRequestBadClient()
    {
        $client = null;
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [
                'HTTP_HOST'   => 'auth-server.tld',
                'REQUEST_URI' => '/authorize',
            ],
            [],
            null,
            'POST',
            'php://input',
            [],
            [
                'oauth_authorize_request' => $this->cryptStub->doEncrypt(json_encode(['user_id' => 123])),
            ],
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
            ],
            [
                'username' => 'alex',
                'password' => 'whisky',
                'action'   => 'approve',
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getMessage(), 'Client authentication failed');
        }
    }

    public function testRespondToAuthorizationRequestBadRedirectUri()
    {
        $client = new ClientEntity();
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [
                'HTTP_HOST'   => 'auth-server.tld',
                'REQUEST_URI' => '/authorize',
            ],
            [],
            null,
            'POST',
            'php://input',
            [],
            [
                'oauth_authorize_request' => $this->cryptStub->doEncrypt(json_encode(['user_id' => 123])),
            ],
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
                'redirect_uri'  =>  'sdfsdf',
            ],
            [
                'username' => 'alex',
                'password' => 'whisky',
                'action'   => 'approve',
            ]
        );

        try {
            /* @var StubResponseType $response */
            $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getMessage(), 'Client authentication failed');
        }
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 7
     */
    public function testRespondToAuthorizationRequestBadCookie()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [
                'HTTP_HOST'   => 'auth-server.tld',
                'REQUEST_URI' => '/authorize',
            ],
            [],
            null,
            'POST',
            'php://input',
            [],
            [
                'oauth_authorize_request' => 'blah',
            ],
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
            ],
            [
                'username' => 'alex',
                'password' => 'whisky',
                'action'   => 'approve',
            ]
        );

        $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
    }

    public function testRespondToAuthorizationRequestTryLogin()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $authCodeRepoMock = $this->getMock(AuthCodeRepositoryInterface::class);
        $authCodeRepoMock->expects($this->once())->method('getNewAuthCode')->willReturn(new AuthCodeEntity());

        $grant = new AuthCodeGrant(
            $authCodeRepoMock,
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [
                'HTTP_HOST'   => 'auth-server.tld',
                'REQUEST_URI' => '/authorize',
            ],
            [],
            null,
            'POST',
            'php://input',
            [],
            [
                'oauth_authorize_request' => $this->cryptStub->doEncrypt(json_encode(['user_id' => null])),
            ],
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
            ],
            [
                'username' => 'alex',
                'password' => 'whisky',
                'action'   => 'approve',
            ]
        );

        $response = $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $this->assertTrue($response instanceof RedirectResponse);

        $response = $response->generateHttpResponse(new Response);
        $this->assertTrue(strstr($response->getHeader('location')[0], 'http://foo/bar') !== false);
    }

    public function testRespondToAuthorizationRequestShowLoginForm()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = null;
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [
                'HTTP_HOST'   => 'auth-server.tld',
                'REQUEST_URI' => '/authorize',
            ],
            [],
            null,
            'POST',
            'php://input',
            [],
            [
                'oauth_authorize_request' => $this->cryptStub->doEncrypt(json_encode(['user_id' => null])),
            ],
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
            ],
            [
                'username' => 'alex',
                'password' => 'whisky',
                'action'   => 'approve',
            ]
        );

        $response = $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $this->assertTrue($response instanceof HtmlResponse);

        $response = $response->generateHttpResponse(new Response);
        $this->assertTrue(strstr($response->getHeader('content-type')[0], 'text/html') !== false);
        $this->assertTrue(strstr((string) $response->getBody(), 'Incorrect username or password') !== false);
    }

    public function testRespondToAuthorizationRequestShowAuthorizeForm()
    {
        $client = new ClientEntity();
        $client->setRedirectUri('http://foo/bar');
        $client->setName('Test Client');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
            new \DateInterval('PT10M')
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setPublicKey(new CryptKey('file://' . __DIR__ . '/../Stubs/public.key'));
        $grant->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest(
            [
                'HTTP_HOST'   => 'auth-server.tld',
                'REQUEST_URI' => '/authorize',
            ],
            [],
            null,
            'POST',
            'php://input',
            [],
            [
                'oauth_authorize_request' => $this->cryptStub->doEncrypt(json_encode(['user_id' => 123])),
            ],
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
            ],
            [
                'username' => 'alex',
                'password' => 'whisky',
            ]
        );

        $response = $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $response = $response->generateHttpResponse(new Response);
        $this->assertTrue($response instanceof ResponseInterface);
        $this->assertTrue(strstr($response->getHeader('set-cookie')[0], 'oauth_authorize_request') !== false);
    }

    public function testRespondToAccessTokenRequest()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();
        $refreshTokenRepositoryMock->method('getNewRefreshToken')->willReturn(new RefreshTokenEntity());

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
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
        $response = $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

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
        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
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
        $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 3
     */
    public function testRespondToAccessTokenRequestMissingCode()
    {
        $client = new ClientEntity();
        $client->setSecret('bar');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
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
        $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
    }

    public function testRespondToAccessTokenRequestExpiredCode()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setRedirectUri('http://foo/bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
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
            $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
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

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $authCodeRepositoryMock = $this->getMockBuilder(AuthCodeRepositoryInterface::class)->getMock();
        $authCodeRepositoryMock->method('isAuthCodeRevoked')->willReturn(true);

        $grant = new AuthCodeGrant(
            $authCodeRepositoryMock,
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
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
            $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
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

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
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
            $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
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

        $userRepositoryMock = $this->getMockBuilder(UserRepositoryInterface::class)->getMock();
        $userEntity = new UserEntity();
        $userRepositoryMock->method('getUserEntityByUserCredentials')->willReturn($userEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
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
            $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));
        } catch (OAuthServerException $e) {
            $this->assertEquals($e->getHint(), 'Cannot decrypt the authorization code');
        }
    }
}
