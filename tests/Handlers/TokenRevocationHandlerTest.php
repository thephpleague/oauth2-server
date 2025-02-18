<?php

declare(strict_types=1);

namespace LeagueTests\Handlers;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Handlers\TokenRevocationHandler;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use LeagueTests\Stubs\ClientEntity;
use PHPUnit\Framework\TestCase;

class TokenRevocationHandlerTest extends TestCase
{
    public function testRespondToRequestForAccessToken(): void
    {
        $client = new ClientEntity();
        $client->setConfidential();
        $client->setIdentifier('client1');

        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())
            ->method('getClientEntity')
            ->with('client1')
            ->willReturn($client);
        $clientRepository
            ->expects($this->once())
            ->method('validateClient')
            ->with('client1', 'secret1', null)
            ->willReturn(true);

        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->expects($this->once())->method('revokeAccessToken')->with('access1');

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'client1',
            'client_secret' => 'secret1',
            'token' => 'token1',
        ]);

        $handler = $this->getMockBuilder(TokenRevocationHandler::class)->onlyMethods(['validateAccessToken'])->getMock();
        $handler->setClientRepository($clientRepository);
        $handler->setAccessTokenRepository($accessTokenRepository);
        $handler->expects($this->once())
            ->method('validateAccessToken')
            ->with($request, 'token1', $client)
            ->willReturn(['access_token', ['jti' => 'access1']]);

        $response = $handler->respondToRequest($request, new Response());
        $response->getBody()->rewind();

        self::assertSame(200, $response->getStatusCode());
    }

    public function testRespondToRequestForRefreshToken(): void
    {
        $client = new ClientEntity();
        $client->setConfidential();
        $client->setIdentifier('client1');

        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())
            ->method('getClientEntity')
            ->with('client1')
            ->willReturn($client);
        $clientRepository
            ->expects($this->once())
            ->method('validateClient')
            ->with('client1', 'secret1', null)
            ->willReturn(true);

        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->expects($this->once())->method('revokeAccessToken')->with('access1');

        $refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $refreshTokenRepository->expects($this->once())->method('revokeRefreshToken')->with('refresh1');

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'client1',
            'client_secret' => 'secret1',
            'token' => 'token1',
        ]);

        $handler = $this->getMockBuilder(TokenRevocationHandler::class)->onlyMethods(['validateRefreshToken'])->getMock();
        $handler->setClientRepository($clientRepository);
        $handler->setAccessTokenRepository($accessTokenRepository);
        $handler->setRefreshTokenRepository($refreshTokenRepository);
        $handler->expects($this->once())
            ->method('validateRefreshToken')
            ->with($request, 'token1', $client)
            ->willReturn(['refresh_token', ['refresh_token_id' => 'refresh1', 'access_token_id' => 'access1']]);

        $response = $handler->respondToRequest($request, new Response());
        $response->getBody()->rewind();

        self::assertSame(200, $response->getStatusCode());
    }

    public function testRespondToRequestForInvalidToken(): void
    {
        $client = new ClientEntity();
        $client->setConfidential();
        $client->setIdentifier('client1');

        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects($this->once())
            ->method('getClientEntity')
            ->with('client1')
            ->willReturn($client);
        $clientRepository
            ->expects($this->once())
            ->method('validateClient')
            ->with('client1', 'secret1', null)
            ->willReturn(true);

        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->expects($this->never())->method('revokeAccessToken');

        $refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $refreshTokenRepository->expects($this->never())->method('revokeRefreshToken');

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'client1',
            'client_secret' => 'secret1',
            'token' => 'token1',
        ]);

        $handler = $this->getMockBuilder(TokenRevocationHandler::class)
            ->onlyMethods(['validateAccessToken', 'validateRefreshToken'])->getMock();
        $handler->setClientRepository($clientRepository);
        $handler->setAccessTokenRepository($accessTokenRepository);
        $handler->setRefreshTokenRepository($refreshTokenRepository);
        $handler->expects($this->once())
            ->method('validateAccessToken')
            ->with($request, 'token1', $client)
            ->willReturn(null);
        $handler->expects($this->once())
            ->method('validateRefreshToken')
            ->with($request, 'token1', $client)
            ->willReturn(null);

        $response = $handler->respondToRequest($request, new Response());
        $response->getBody()->rewind();

        self::assertSame(200, $response->getStatusCode());
    }
}
