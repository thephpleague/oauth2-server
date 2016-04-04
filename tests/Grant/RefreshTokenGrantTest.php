<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Jwt\AccessTokenConverter;
use League\OAuth2\Server\Jwt\BearerTokenResponse;
use League\OAuth2\Server\MessageEncryption;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseFactory;
use League\OAuth2\Server\TemplateRenderer\RendererInterface;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\ScopeEntity;
use Zend\Diactoros\ServerRequest;

class RefreshTokenGrantTest extends \PHPUnit_Framework_TestCase
{
    /**
     * @var MessageEncryption
     */
    protected $messageEncryption;
    /**
     * @var ResponseFactory
     */
    private $responseFactory;

    public function setUp()
    {
        $this->messageEncryption = new MessageEncryption(
            'file://' . __DIR__ . '/../Stubs/private.key',
            'file://' . __DIR__ . '/../Stubs/public.key'
        );

        $this->responseFactory = new ResponseFactory(
            new AccessTokenConverter('file://' . __DIR__ . '/../Stubs/private.key'),
            $this->getMock(RendererInterface::class)
        );
    }

    public function testGetIdentifier()
    {
        $refreshTokenRepositoryMock = $this->getMock(RefreshTokenRepositoryInterface::class);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock, $this->messageEncryption);
        $this->assertEquals('refresh_token', $grant->getIdentifier());
    }

    public function testRespondToRequest()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeEntity = new ScopeEntity();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock
            ->expects($this->once())
            ->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock
            ->expects($this->once())
            ->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock, $this->messageEncryption);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $oldRefreshToken = $this->messageEncryption->encrypt(
            json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => time() + 3600,
                ]
            )
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
            ]
        );

        $responseType = $grant->respondToRequest($serverRequest, $this->responseFactory, new \DateInterval('PT5M'));
        $this->assertTrue($responseType instanceof BearerTokenResponse);
    }

    public function testRespondToReducedScopes()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $scope = new ScopeEntity();
        $scope->setIdentifier('foo');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock, $this->messageEncryption);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $oldRefreshToken = $this->messageEncryption->encrypt(
            json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo', 'bar'],
                    'user_id'          => 123,
                    'expire_time'      => time() + 3600,
                ]
            )
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
                'scope'         => 'foo',
            ]
        );

        $responseType = $grant->respondToRequest($serverRequest, $this->responseFactory, new \DateInterval('PT5M'));

        $this->assertTrue($responseType instanceof BearerTokenResponse);
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 5
     */
    public function testRespondToUnexpectedScope()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $scope = new ScopeEntity();
        $scope->setIdentifier('foobar');
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scope);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock, $this->messageEncryption);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $oldRefreshToken = $this->messageEncryption->encrypt(
            json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo', 'bar'],
                    'user_id'          => 123,
                    'expire_time'      => time() + 3600,
                ]
            )
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
                'scope'         => 'foobar',
            ]
        );

        $grant->respondToRequest($serverRequest, $this->responseFactory, new \DateInterval('PT5M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 3
     */
    public function testRespondToRequestMissingOldToken()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock, $this->messageEncryption);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
            ]
        );

        $grant->respondToRequest($serverRequest, $this->responseFactory, new \DateInterval('PT5M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 8
     */
    public function testRespondToRequestInvalidOldToken()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock, $this->messageEncryption);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $oldRefreshToken = 'foobar';

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
            ]
        );

        $grant->respondToRequest($serverRequest, $this->responseFactory, new \DateInterval('PT5M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 8
     */
    public function testRespondToRequestClientMismatch()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();


        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('persistNewRefreshToken')->willReturnSelf();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock, $this->messageEncryption);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $oldRefreshToken = $this->messageEncryption->encrypt(
            json_encode(
                [
                    'client_id'        => 'bar',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => time() + 3600,
                ]
            )
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
            ]
        );

        $grant->respondToRequest($serverRequest, $this->responseFactory, new \DateInterval('PT5M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 8
     */
    public function testRespondToRequestExpiredToken()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock, $this->messageEncryption);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $oldRefreshToken = $this->messageEncryption->encrypt(
            json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => time() - 3600,
                ]
            )
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
            ]
        );

        $grant->respondToRequest($serverRequest, $this->responseFactory, new \DateInterval('PT5M'));
    }

    /**
     * @expectedException \League\OAuth2\Server\Exception\OAuthServerException
     * @expectedExceptionCode 8
     */
    public function testRespondToRequestRevokedToken()
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock = $this->getMockBuilder(RefreshTokenRepositoryInterface::class)->getMock();
        $refreshTokenRepositoryMock->method('isRefreshTokenRevoked')->willReturn(true);

        $grant = new RefreshTokenGrant($refreshTokenRepositoryMock, $this->messageEncryption);
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);

        $oldRefreshToken = $this->messageEncryption->encrypt(
            json_encode(
                [
                    'client_id'        => 'foo',
                    'refresh_token_id' => 'zyxwvu',
                    'access_token_id'  => 'abcdef',
                    'scopes'           => ['foo'],
                    'user_id'          => 123,
                    'expire_time'      => time() + 3600,
                ]
            )
        );

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
                'refresh_token' => $oldRefreshToken,
            ]
        );

        $grant->respondToRequest($serverRequest, $this->responseFactory, new \DateInterval('PT5M'));
    }
}
