<?php

declare(strict_types=1);

namespace LeagueTests\Handlers;

use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Handlers\TokenIntrospectionHandler;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\IntrospectionResponseTypeInterface;
use LeagueTests\Stubs\ClientEntity;
use PHPUnit\Framework\TestCase;

class TokenIntrospectionHandlerTest extends TestCase
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

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'client1',
            'client_secret' => 'secret1',
            'token' => 'token1',
        ]);

        $handler = $this->getMockBuilder(TokenIntrospectionHandler::class)->onlyMethods(['validateToken'])->getMock();
        $handler->setClientRepository($clientRepository);
        $handler->expects(self::once())
            ->method('validateToken')
            ->with($request, $client)
            ->willReturn(['access_token', ['jti' => 'access1']]);

        $response = $handler->respondToRequest($request, new Response());
        $response->getBody()->rewind();

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json; charset=UTF-8', $response->getHeaderLine('Content-Type'));
        self::assertSame([
            'active' => true,
            'scope' => '',
            'token_type' => 'Bearer',
            'jti' => 'access1',
        ], json_decode($response->getBody()->getContents(), true));
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

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'client1',
            'client_secret' => 'secret1',
            'token' => 'token1',
        ]);

        $handler = $this->getMockBuilder(TokenIntrospectionHandler::class)->onlyMethods(['validateToken'])->getMock();
        $handler->setClientRepository($clientRepository);
        $handler->expects(self::once())
            ->method('validateToken')
            ->with($request, $client)
            ->willReturn(['refresh_token', ['refresh_token_id' => 'refresh1']]);

        $response = $handler->respondToRequest($request, new Response());
        $response->getBody()->rewind();

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json; charset=UTF-8', $response->getHeaderLine('Content-Type'));
        self::assertSame([
            'active' => true,
            'scope' => '',
            'jti' => 'refresh1',
        ], json_decode($response->getBody()->getContents(), true));
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

        $request = (new ServerRequest())->withParsedBody([
            'client_id' => 'client1',
            'client_secret' => 'secret1',
            'token' => 'token1',
        ]);

        $handler = $this->getMockBuilder(TokenIntrospectionHandler::class)
            ->onlyMethods(['validateToken'])->getMock();
        $handler->setClientRepository($clientRepository);
        $handler->expects(self::once())
            ->method('validateToken')
            ->with($request, $client)
            ->willReturn([null, null]);

        $response = $handler->respondToRequest($request, new Response());
        $response->getBody()->rewind();

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json; charset=UTF-8', $response->getHeaderLine('Content-Type'));
        self::assertSame(['active' => false], json_decode($response->getBody()->getContents(), true));
    }

    public function testSetResponseType(): void
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
            'token' => 'token1',
        ]);

        $response = new Response();

        $responseType = $this->createMock(IntrospectionResponseTypeInterface::class);
        $responseType->expects(self::once())->method('setActive')->with(true);
        $responseType->expects(self::once())->method('setTokenType')->with('foo');
        $responseType->expects(self::once())->method('setTokenData')->with(['bar' => 'baz']);
        $responseType->expects(self::once())->method('generateHttpResponse')->with($response)->willReturnArgument(0);

        $handler = $this->getMockBuilder(TokenIntrospectionHandler::class)->onlyMethods(['validateToken'])->getMock();
        $handler->setClientRepository($clientRepository);
        $handler->setResponseType($responseType);
        $handler->expects(self::once())
            ->method('validateToken')
            ->with($request, $client)
            ->willReturn(['foo', ['bar' => 'baz']]);

        $result = $handler->respondToRequest($request, $response);

        self::assertSame($response, $result);
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

        $handler = new TokenIntrospectionHandler();
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

        $handler = new TokenIntrospectionHandler();
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
