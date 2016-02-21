<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\Entities\ClientEntity;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use League\OAuth2\Server\Utils\KeyCrypt;
use LeagueTests\Stubs\StubResponseType;
use LeagueTests\Stubs\UserEntity;
use Psr\Http\Message\ResponseInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

class AuthCodeGrantTest extends \PHPUnit_Framework_TestCase
{
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
            []
            ,
            null,
            null,
            'php://input',
            $headers = [],
            $cookies = [],
            $queryParams = [
                'response_type' => 'code',
                'client_id'     => 'foo'
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

        $grant = new AuthCodeGrant(
            $this->getMock(AuthCodeRepositoryInterface::class),
            $this->getMock(RefreshTokenRepositoryInterface::class),
            $userRepositoryMock,
            new \DateInterval('PT10M'),
            '',
            ''
        );
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setPathToPublicKey('file://'.__DIR__.'/../Utils/public.key');
        $grant->setPathToPrivateKey('file://'.__DIR__.'/../Utils/private.key');

        $request = new ServerRequest(
            [
                'HTTP_HOST'   => 'auth-server.tld',
                'REQUEST_URI' => '/authorize',
            ],
            []
            ,
            null,
            'POST',
            'php://input',
            [],
            [
                'oauth_authorize_request' => KeyCrypt::encrypt(
                    json_encode(['user_id' => 123]),
                    'file://'.__DIR__.'/../Utils/private.key'
                )
            ],
            [
                'response_type' => 'code',
                'client_id'     => 'foo',
            ],
            [
                'username' => 'alex',
                'password' => 'whisky',
                'action'   => 'approve'
            ]
        );

        $response = $grant->respondToRequest($request, new StubResponseType(), new \DateInterval('PT10M'));

        $this->assertTrue($response instanceof ResponseInterface);
    }
}
