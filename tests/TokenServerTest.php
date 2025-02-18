<?php

declare(strict_types=1);

namespace LeagueTests;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Handlers\TokenHandlerInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\TokenServer;
use LeagueTests\Stubs\ClientEntity;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function base64_encode;
use function random_bytes;

class TokenServerTest extends TestCase
{
    public function testRespondToTokenRevocationRequest(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');

        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())->method('getClientEntity')
            ->with('foo')
            ->willReturn($client);

        $server = $this->getTokenServer($clientRepository);

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'client_secret' => 'bar',
            'token' => 'foobar',
        ]);

        $result = $server->respondToTokenRevocationRequest($request, new Response());

        self::assertSame(200, $result->getStatusCode());
    }

    public function testRespondToTokenIntrospectionRequest(): void
    {
        $client = new ClientEntity();
        $client->setIdentifier('foo');

        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())->method('getClientEntity')
            ->with('foo')
            ->willReturn($client);

        $server = $this->getTokenServer($clientRepository);

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'foo',
            'client_secret' => 'bar',
            'token' => 'foobar',
        ]);

        $result = $server->respondToTokenIntrospectionRequest($request, new Response());
        $result->getBody()->rewind();

        self::assertSame(200, $result->getStatusCode());
        self::assertSame('application/json; charset=UTF-8', $result->getHeaderLine('Content-Type'));
        self::assertSame('{"active":false}', $result->getBody()->getContents());
    }

    public function testSetTokenRevocationHandler(): void
    {
        $server = $this->getTokenServer();

        $request = $this->createMock(ServerRequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $revocationHandler = $this->getMockBuilder(TokenHandlerInterface::class)->getMock();
        $revocationHandler->expects($this->once())->method('respondToRequest')
            ->with($request, $response)
            ->willReturn($response);

        $server->setTokenRevocationHandler($revocationHandler);

        $result = $server->respondToTokenRevocationRequest($request, $response);

        self::assertSame($response, $result);
    }

    public function testSetTokenIntrospectionHandler(): void
    {
        $server = $this->getTokenServer();

        $request = $this->createMock(ServerRequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);

        $introspectionHandler = $this->getMockBuilder(TokenHandlerInterface::class)->getMock();
        $introspectionHandler->expects($this->once())->method('respondToRequest')
            ->with($request, $response)
            ->willReturn($response);

        $server->setTokenIntrospectionHandler($introspectionHandler);

        $result = $server->respondToTokenIntrospectionRequest($request, $response);

        self::assertSame($response, $result);
    }

    private function getTokenServer(
        ?ClientRepositoryInterface $clientRepository = null,
        ?AccessTokenRepositoryInterface $accessTokenRepository = null,
        ?RefreshTokenRepositoryInterface $refreshTokenRepository = null
    ): TokenServer {
        return new TokenServer(
            $clientRepository ?? $this->createMock(ClientRepositoryInterface::class),
            $accessTokenRepository ?? $this->createMock(AccessTokenRepositoryInterface::class),
            $refreshTokenRepository ?? $this->createMock(RefreshTokenRepositoryInterface::class),
            'file://' . __DIR__ . '/Stubs/public.key',
            base64_encode(random_bytes(36))
        );
    }
}
