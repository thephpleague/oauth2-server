<?php

namespace LeagueTests\Middleware;

use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Middleware\Psr15ResourceServerMiddleware;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResourceServer;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

class Psr15ResourceServerMiddlewareTest extends TestCase
{
    public function testValidResponse()
    {
        $server = new ResourceServer(
                $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
                'file://' . __DIR__ . '/../Stubs/public.key'
        );

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('test');
        $accessToken->setUserIdentifier(123);
        $accessToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));
        $accessToken->setClient($client);

        $token = $accessToken->convertToJWT(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', sprintf('Bearer %s', $token));

        $responseFactoryMock = $this->getMockBuilder(ResponseFactoryInterface::class)->getMock();
        $responseFactoryMock->method('createResponse')->willReturn(new Response());
        $requestHandlerMock = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $requestHandlerMock->method('handle')->willReturn(new Response());

        $middleware = new Psr15ResourceServerMiddleware($server, $responseFactoryMock);
        $response = $middleware->process(
                $request,
                $requestHandlerMock
        );

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testValidResponseExpiredToken()
    {
        $server = new ResourceServer(
                $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
                'file://' . __DIR__ . '/../Stubs/public.key'
        );

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('test');
        $accessToken->setUserIdentifier(123);
        $accessToken->setExpiryDateTime((new \DateTime())->sub(new \DateInterval('PT1H')));
        $accessToken->setClient($client);

        $token = $accessToken->convertToJWT(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', sprintf('Bearer %s', $token));

        $responseFactoryMock = $this->getMockBuilder(ResponseFactoryInterface::class)->getMock();
        $responseFactoryMock->method('createResponse')->willReturn(new Response());
        $requestHandlerMock = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $requestHandlerMock->method('handle')->willReturn(new Response());

        $middleware = new Psr15ResourceServerMiddleware($server, $responseFactoryMock);
        $response = $middleware->process(
                $request,
                $requestHandlerMock
        );

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testErrorResponse()
    {
        $server = new ResourceServer(
                $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
                'file://' . __DIR__ . '/../Stubs/public.key'
        );

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', '');

        $responseFactoryMock = $this->getMockBuilder(ResponseFactoryInterface::class)->getMock();
        $responseFactoryMock->method('createResponse')->willReturn(new Response());
        $requestHandlerMock = $this->getMockBuilder(RequestHandlerInterface::class)->getMock();
        $requestHandlerMock->method('handle')->willReturn(new Response());

        $middleware = new Psr15ResourceServerMiddleware($server, $responseFactoryMock);
        $response = $middleware->process(
                $request,
                $requestHandlerMock
        );

        $this->assertEquals(401, $response->getStatusCode());
    }
}
