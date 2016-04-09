<?php

namespace LeagueTests\Grant;

use Lcobucci\JWT\Builder;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Jwt\AccessTokenConverter;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseFactory;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use League\OAuth2\Server\ResponseTypes\ResponseFactoryInterface;
use League\OAuth2\Server\TemplateRenderer\RendererInterface;
use LeagueTests\Stubs\ClientEntity;
use Zend\Diactoros\ServerRequest;

class ClientCredentialsGrantTest extends \PHPUnit_Framework_TestCase
{
    public function testGetIdentifier()
    {
        $grant = new ClientCredentialsGrant($this->getMock(ResponseFactoryInterface::class));
        $this->assertEquals('client_credentials', $grant->getIdentifier());
    }

    public function testRespondToRequest()
    {
        $responseFactory = new ResponseFactory(
            new AccessTokenConverter(new Builder(), 'file://' . __DIR__ . '/../Stubs/private.key'),
            $this->getMock(RendererInterface::class)
        );

        $client = new ClientEntity();
        $client->setSecret('bar');
        $clientRepositoryMock = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepositoryMock->method('getClientEntity')->willReturn($client);

        $accessTokenRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessTokenRepositoryMock->method('persistNewAccessToken')->willReturnSelf();

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $grant = new ClientCredentialsGrant($responseFactory);
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

        $responseType = $grant->respondToRequest($serverRequest, new \DateInterval('PT5M'));

        $this->assertTrue($responseType instanceof BearerTokenResponse);
    }
}
