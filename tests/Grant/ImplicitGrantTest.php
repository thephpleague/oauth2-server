<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\HtmlResponse;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\CryptTraitStub;
use LeagueTests\Stubs\StubResponseType;
use LeagueTests\Stubs\UserEntity;
use Zend\Diactoros\Response;
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
        $grant = new ImplicitGrant($this->getMock(UserRepositoryInterface::class));

        $this->assertEquals('implicit', $grant->getIdentifier());
    }

    public function testCanRespondToRequest()
    {
        $grant = new ImplicitGrant($this->getMock(UserRepositoryInterface::class));

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            [],
            [],
            [
                'response_type' => 'token',
            ]
        );

        $this->assertTrue($grant->canRespondToRequest($request));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 9
     */
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

        $grant = new ImplicitGrant($userRepositoryMock);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setPublicKeyPath('file://' . __DIR__ . '/../Stubs/public.key');
        $grant->setPrivateKeyPath('file://' . __DIR__ . '/../Stubs/private.key');

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
            [],
            [
                'response_type' => 'token',
                'client_id'     => 'foo',
                'state'         => 'foobar',
            ],
            [
                'username' => 'alex',
                'password' => 'whisky',
                'action'   => 'approve',
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
        $grant = new ImplicitGrant($this->getMock(UserRepositoryInterface::class));
        $grant->setPublicKeyPath('file://' . __DIR__ . '/../Stubs/public.key');
        $grant->setPrivateKeyPath('file://' . __DIR__ . '/../Stubs/private.key');

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
                'response_type' => 'token',
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

        $grant = new ImplicitGrant($this->getMock(UserRepositoryInterface::class));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPublicKeyPath('file://' . __DIR__ . '/../Stubs/public.key');
        $grant->setPrivateKeyPath('file://' . __DIR__ . '/../Stubs/private.key');

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
                'response_type' => 'token',
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

        $grant = new ImplicitGrant($this->getMock(UserRepositoryInterface::class));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPublicKeyPath('file://' . __DIR__ . '/../Stubs/public.key');
        $grant->setPrivateKeyPath('file://' . __DIR__ . '/../Stubs/private.key');

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
                'response_type' => 'token',
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

        $grant = new ImplicitGrant($this->getMock(UserRepositoryInterface::class));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPublicKeyPath('file://' . __DIR__ . '/../Stubs/public.key');
        $grant->setPrivateKeyPath('file://' . __DIR__ . '/../Stubs/private.key');

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
                'response_type' => 'token',
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

        $grant = new ImplicitGrant($this->getMock(UserRepositoryInterface::class));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setPublicKeyPath('file://' . __DIR__ . '/../Stubs/public.key');
        $grant->setPrivateKeyPath('file://' . __DIR__ . '/../Stubs/private.key');

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
                'response_type' => 'token',
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
        $this->assertTrue(strstr((string) $response->getBody(), 'Incorrect username or password') !== false);
    }

    public function testRespondToAuthorizationRequestShowAuthorizeForm()
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

        $grant = new ImplicitGrant($this->getMock(UserRepositoryInterface::class));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setPublicKeyPath('file://' . __DIR__ . '/../Stubs/public.key');
        $grant->setPrivateKeyPath('file://' . __DIR__ . '/../Stubs/private.key');

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

        $this->assertTrue($response instanceof HtmlResponse);

        $response = $response->generateHttpResponse(new Response);
        $this->assertTrue(strstr($response->getHeader('set-cookie')[0], 'oauth_authorize_request') !== false);
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

        $grant = new ImplicitGrant($this->getMock(UserRepositoryInterface::class));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPublicKeyPath('file://' . __DIR__ . '/../Stubs/public.key');
        $grant->setPrivateKeyPath('file://' . __DIR__ . '/../Stubs/private.key');

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
}
