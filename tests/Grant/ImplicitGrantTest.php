<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\Entities\ClientEntity;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\ImplicitGrant;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\Utils\KeyCrypt;
use LeagueTests\Stubs\StubResponseType;
use LeagueTests\Stubs\UserEntity;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\ServerRequest;

class ImplicitGrantTest extends \PHPUnit_Framework_TestCase
{
    public function testGetIdentifier()
    {
        $grant = new ImplicitGrant(
            $this->getMock(UserRepositoryInterface::class),
            'foo/bar.php',
            'foo/bar.php'
        );

        $this->assertEquals('implicit', $grant->getIdentifier());
    }

    public function testCanRespondToRequest()
    {
        $grant = new ImplicitGrant(
            $this->getMock(UserRepositoryInterface::class),
            'foo/bar.php',
            'foo/bar.php'
        );

        $request = new ServerRequest(
            [],
            [],
            null,
            null,
            'php://input',
            [],
            [],
            [
                'response_type' => 'token'
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

        $grant = new ImplicitGrant($userRepositoryMock, 'foo', 'foo');
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

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

        $response = $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $this->assertTrue($response instanceof ResponseInterface);
        $this->assertTrue(strstr($response->getHeader('location')[0], 'http://foo/bar') !== false);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 3
     */
    public function testRespondToAuthorizationRequestMissingClientId()
    {
        $grant = new ImplicitGrant(
            $this->getMock(UserRepositoryInterface::class),
            'foo/bar.php',
            'foo/bar.php'
        );
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

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
                'oauth_authorize_request' => KeyCrypt::encrypt(
                    json_encode(['user_id' => 123]),
                    'file://' . __DIR__ . '/../Utils/private.key'
                ),
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

        $response = $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $this->assertTrue($response instanceof ResponseInterface);
    }

    public function testRespondToAuthorizationRequestBadClient()
    {
        $client = null;
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $grant = new ImplicitGrant(
            $this->getMock(UserRepositoryInterface::class),
            'foo/bar.php',
            'foo/bar.php'
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

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
                'oauth_authorize_request' => KeyCrypt::encrypt(
                    json_encode(['user_id' => 123]),
                    'file://' . __DIR__ . '/../Utils/private.key'
                ),
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

        $grant = new ImplicitGrant(
            $this->getMock(UserRepositoryInterface::class),
            'foo/bar.php',
            'foo/bar.php'
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

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
                'oauth_authorize_request' => KeyCrypt::encrypt(
                    json_encode(['user_id' => 123]),
                    'file://' . __DIR__ . '/../Utils/private.key'
                ),
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

        $grant = new ImplicitGrant(
            $this->getMock(UserRepositoryInterface::class),
            'foo/bar.php',
            'foo/bar.php'
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

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

        $response = $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $this->assertTrue($response instanceof ResponseInterface);
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

        $grant = new ImplicitGrant($this->getMock(UserRepositoryInterface::class));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

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
                'oauth_authorize_request' => KeyCrypt::encrypt(
                    json_encode(['user_id' => null]),
                    'file://' . __DIR__ . '/../Utils/private.key'
                ),
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
        $this->assertTrue($response instanceof ResponseInterface);
        $this->assertTrue(strstr($response->getHeader('content-type')[0], 'text/html') !== false);
        $this->assertTrue(strstr($response->getBody()->getContents(), 'Incorrect username or password') !== false);
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

        $grant = new ImplicitGrant($this->getMock(UserRepositoryInterface::class));
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

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
                'oauth_authorize_request' => KeyCrypt::encrypt(
                    json_encode(['user_id' => 123]),
                    'file://' . __DIR__ . '/../Utils/private.key'
                ),
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

        $this->assertTrue($response instanceof ResponseInterface);
        $this->assertTrue(strstr($response->getHeader('set-cookie')[0], 'oauth_authorize_request') !== false);
    }

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
        $grant->setPathToPublicKey('file://' . __DIR__ . '/../Utils/public.key');
        $grant->setPathToPrivateKey('file://' . __DIR__ . '/../Utils/private.key');

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
                'oauth_authorize_request' => KeyCrypt::encrypt(
                    json_encode(['user_id' => 123]),
                    'file://' . __DIR__ . '/../Utils/private.key'
                ),
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

        $response = $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $this->assertTrue($response instanceof ResponseInterface);
        $this->assertTrue(strstr($response->getHeader('location')[0], 'http://foo/bar') !== false);
        $this->assertTrue(strstr($response->getHeader('location')[0], 'access_denied') !== false);
    }
}
