<?php

namespace LeagueTests\Middleware;

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Middleware\Psr15AuthorizationServerMiddleware;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequestFactory;

class Psr15AuthorizationServerMiddlewareTest extends TestCase
{
    const DEFAULT_SCOPE = 'basic';

    public function testValidResponse()
    {
        $client = new ClientEntity();
        $client->setConfidential();

        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepository->method('getClientEntity')->willReturn($client);

        $scopeEntity = new ScopeEntity;
        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('getScopeEntityByIdentifier')->willReturn($scopeEntity);
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $accessRepositoryMock = $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock();
        $accessRepositoryMock->method('getNewToken')->willReturn(new AccessTokenEntity());

        $server = new AuthorizationServer(
                $clientRepository,
                $accessRepositoryMock,
                $scopeRepositoryMock,
                'file://' . __DIR__ . '/../Stubs/private.key',
                base64_encode(random_bytes(36)),
                new StubResponseType()
        );

        $server->setDefaultScope(self::DEFAULT_SCOPE);
        $server->enableGrantType(new ClientCredentialsGrant());

        $_POST['grant_type'] = 'client_credentials';
        $_POST['client_id'] = 'foo';
        $_POST['client_secret'] = 'bar';

        $request = ServerRequestFactory::fromGlobals();

        $responseFactoryMock = $this->getMockBuilder(ResponseFactoryInterface::class)->getMock();
        $responseFactoryMock->method('createResponse')->willReturn(new Response());
        $requestHandlerMock = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $requestHandlerMock->method('handle')->willReturn(new Response());

        $middleware = new Psr15AuthorizationServerMiddleware($server, $responseFactoryMock);
        $response = $middleware->process(
                $request,
                $requestHandlerMock
        );

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testOAuthErrorResponse()
    {
        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepository->method('getClientEntity')->willReturn(null);

        $server = new AuthorizationServer(
                $clientRepository,
                $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
                $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock(),
                'file://' . __DIR__ . '/../Stubs/private.key',
                base64_encode(random_bytes(36)),
                new StubResponseType()
        );

        $server->enableGrantType(new ClientCredentialsGrant(), new \DateInterval('PT1M'));

        $_POST['grant_type'] = 'client_credentials';
        $_POST['client_id'] = 'foo';
        $_POST['client_secret'] = 'bar';

        $request = ServerRequestFactory::fromGlobals();

        $responseFactoryMock = $this->getMockBuilder(ResponseFactoryInterface::class)->getMock();
        $responseFactoryMock->method('createResponse')->willReturn(new Response());
        $requestHandlerMock = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $requestHandlerMock->method('handle')->willReturn(new Response());

        $middleware = new Psr15AuthorizationServerMiddleware($server, $responseFactoryMock);

        $response = $middleware->process(
                $request,
                $requestHandlerMock
        );

        $this->assertEquals(401, $response->getStatusCode());
    }
}
