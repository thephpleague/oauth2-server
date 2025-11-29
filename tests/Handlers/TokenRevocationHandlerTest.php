<?php

declare(strict_types=1);

namespace LeagueTests\Handlers;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
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
        $clientRepository->expects(self::once())
            ->method('getClientEntity')
            ->with('client1')
            ->willReturn($client);
        $clientRepository
            ->expects(self::once())
            ->method('validateClient')
            ->with('client1', 'secret1', null)
            ->willReturn(true);

        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->expects(self::once())->method('revokeAccessToken')->with('access1');

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'client1',
            'client_secret' => 'secret1',
            'token' => 'token1',
        ]);

        $handler = $this->getMockBuilder(TokenRevocationHandler::class)->onlyMethods(['validateToken'])->getMock();
        $handler->setClientRepository($clientRepository);
        $handler->setAccessTokenRepository($accessTokenRepository);
        $handler->expects(self::once())
            ->method('validateToken')
            ->with($request, $client)
            ->willReturn(['type' => 'access_token', 'data' => ['jti' => 'access1']]);

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
        $clientRepository->expects(self::once())
            ->method('getClientEntity')
            ->with('client1')
            ->willReturn($client);
        $clientRepository
            ->expects(self::once())
            ->method('validateClient')
            ->with('client1', 'secret1', null)
            ->willReturn(true);

        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->expects(self::once())->method('revokeAccessToken')->with('access1');

        $refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $refreshTokenRepository->expects(self::once())->method('revokeRefreshToken')->with('refresh1');

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'client1',
            'client_secret' => 'secret1',
            'token' => 'token1',
        ]);

        $handler = $this->getMockBuilder(TokenRevocationHandler::class)->onlyMethods(['validateToken'])->getMock();
        $handler->setClientRepository($clientRepository);
        $handler->setAccessTokenRepository($accessTokenRepository);
        $handler->setRefreshTokenRepository($refreshTokenRepository);
        $handler->expects(self::once())
            ->method('validateToken')
            ->with($request, $client)
            ->willReturn(['type' => 'refresh_token', 'data' => [
                'refresh_token_id' => 'refresh1',
                'access_token_id' => 'access1',
            ]]);

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
        $clientRepository->expects(self::once())
            ->method('getClientEntity')
            ->with('client1')
            ->willReturn($client);
        $clientRepository
            ->expects(self::once())
            ->method('validateClient')
            ->with('client1', 'secret1', null)
            ->willReturn(true);

        $accessTokenRepository = $this->createMock(AccessTokenRepositoryInterface::class);
        $accessTokenRepository->expects(self::never())->method('revokeAccessToken');

        $refreshTokenRepository = $this->createMock(RefreshTokenRepositoryInterface::class);
        $refreshTokenRepository->expects(self::never())->method('revokeRefreshToken');

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'client1',
            'client_secret' => 'secret1',
            'token' => 'token1',
        ]);

        $handler = $this->getMockBuilder(TokenRevocationHandler::class)
            ->onlyMethods(['validateToken'])->getMock();
        $handler->setClientRepository($clientRepository);
        $handler->setAccessTokenRepository($accessTokenRepository);
        $handler->setRefreshTokenRepository($refreshTokenRepository);
        $handler->expects(self::once())
            ->method('validateToken')
            ->with($request, $client)
            ->willReturn(null);

        $response = $handler->respondToRequest($request, new Response());
        $response->getBody()->rewind();

        self::assertSame(200, $response->getStatusCode());
    }

    public function testRespondToRequestInvalidClientCredentials(): void
    {
        $client = new ClientEntity();
        $client->setConfidential();
        $client->setIdentifier('client1');

        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects(self::once())
            ->method('getClientEntity')
            ->with('client1')
            ->willReturn($client);
        $clientRepository
            ->expects(self::once())
            ->method('validateClient')
            ->with('client1', 'secret1', null)
            ->willReturn(false);

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'client1',
            'client_secret' => 'secret1',
            'token' => 'token1',
        ]);

        $handler = new TokenRevocationHandler();
        $handler->setClientRepository($clientRepository);

        try {
            $handler->respondToRequest($request, new Response());
        } catch (OAuthServerException $e) {
            self::assertSame(4, $e->getCode());
            self::assertSame('invalid_client', $e->getErrorType());

            return;
        }

        self::fail('The expected exception was not thrown');
    }

    public function testRespondToRequestMissingToken(): void
    {
        $client = new ClientEntity();
        $client->setConfidential();
        $client->setIdentifier('client1');

        $clientRepository = $this->createMock(ClientRepositoryInterface::class);
        $clientRepository->expects(self::once())
            ->method('getClientEntity')
            ->with('client1')
            ->willReturn($client);
        $clientRepository
            ->expects(self::once())
            ->method('validateClient')
            ->with('client1', 'secret1', null)
            ->willReturn(true);

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'client1',
            'client_secret' => 'secret1',
        ]);

        $handler = new TokenRevocationHandler();
        $handler->setClientRepository($clientRepository);

        try {
            $handler->respondToRequest($request, new Response());
        } catch (OAuthServerException $e) {
            self::assertSame(3, $e->getCode());
            self::assertSame('invalid_request', $e->getErrorType());

            return;
        }

        self::fail('The expected exception was not thrown');
    }
}
