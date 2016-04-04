<?php

namespace LeagueTests\Grant;

use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Jwt\AccessTokenConverter;
use League\OAuth2\Server\Jwt\BearerTokenResponse;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseFactory;
use League\OAuth2\Server\TemplateRenderer\RendererInterface;
use LeagueTests\Stubs\ClientEntity;
use Zend\Diactoros\ServerRequest;

class ClientCredentialsGrantTest extends \PHPUnit_Framework_TestCase
{
    public function testGetIdentifier()
    {
        $grant = new ClientCredentialsGrant();
        $this->assertEquals('client_credentials', $grant->getIdentifier());
    }

    public function testRespondToRequest()
    {
        $client = new ClientEntity();
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ClientCredentialsGrant();
        $grant->setClientRepository($clientRepositoryMock);
        $grant->setAccessTokenRepository($accessTokenRepositoryMock);
        $grant->setScopeRepository($scopeRepositoryMock);

        $serverRequest = new ServerRequest();
        $serverRequest = $serverRequest->withParsedBody(
            [
                'client_id'     => 'foo',
                'client_secret' => 'bar',
            ]
        );

        $responseFactory = new ResponseFactory(
            new AccessTokenConverter('file://' . __DIR__ . '/../Stubs/private.key'),
            $this->getMock(RendererInterface::class)
        );

        $responseType = $grant->respondToRequest($serverRequest, $responseFactory, new \DateInterval('PT5M'));

        $this->assertTrue($responseType instanceof BearerTokenResponse);
    }
}
