<?php

declare(strict_types=1);

namespace LeagueTests\Middleware;

use DateInterval;
use DateTimeImmutable;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequest;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Middleware\ResourceServerMiddleware;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\ResourceServer;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use PHPUnit\Framework\TestCase;

use function func_get_args;
use function sprintf;

class ResourceServerMiddlewareTest extends TestCase
{
    public function testValidResponse(): void
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
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->add(new DateInterval('PT1H')));
        $accessToken->setClient($client);
        $accessToken->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $token = (string) $accessToken;

        $request = (new ServerRequest())->withHeader('authorization', sprintf('Bearer %s', $token));

        $middleware = new ResourceServerMiddleware($server);
        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                self::assertEquals('test', func_get_args()[0]->getAttribute('oauth_access_token_id'));

                return func_get_args()[1];
            }
        );

        self::assertEquals(200, $response->getStatusCode());
    }

    public function testValidResponseExpiredToken(): void
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
        $accessToken->setExpiryDateTime((new DateTimeImmutable())->sub(new DateInterval('PT1H')));
        $accessToken->setClient($client);
        $accessToken->setPrivateKey(new CryptKey('file://' . __DIR__ . '/../Stubs/private.key'));

        $token = (string) $accessToken;

        $request = (new ServerRequest())->withHeader('authorization', sprintf('Bearer %s', $token));

        $middleware = new ResourceServerMiddleware($server);
        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                self::assertEquals('test', func_get_args()[0]->getAttribute('oauth_access_token_id'));

                return func_get_args()[1];
            }
        );

        self::assertEquals(401, $response->getStatusCode());
    }

    public function testErrorResponse(): void
    {
        $server = new ResourceServer(
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/../Stubs/public.key'
        );

        $request = (new ServerRequest())->withHeader('authorization', '');

        $middleware = new ResourceServerMiddleware($server);
        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                return func_get_args()[1];
            }
        );

        self::assertEquals(401, $response->getStatusCode());
    }
}
