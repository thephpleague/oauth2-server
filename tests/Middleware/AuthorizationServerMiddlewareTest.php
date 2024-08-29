<?php

declare(strict_types=1);

namespace LeagueTests\Middleware;

use DateInterval;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\ServerRequestFactory;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Middleware\AuthorizationServerMiddleware;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use LeagueTests\Stubs\AccessTokenEntity;
use LeagueTests\Stubs\ClientEntity;
use LeagueTests\Stubs\ScopeEntity;
use LeagueTests\Stubs\StubResponseType;
use PHPUnit\Framework\TestCase;

use function base64_encode;
use function func_get_args;
use function random_bytes;

class AuthorizationServerMiddlewareTest extends TestCase
{
    private const DEFAULT_SCOPE = 'basic';

    public function testValidResponse(): void
    {
        $client = new ClientEntity();
        $client->setConfidential();
        $client->setRedirectUri('http://foo/bar');

        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepository->method('getClientEntity')->willReturn($client);
        $clientRepository->method('validateClient')->willReturn(true);

        $scopeEntity = new ScopeEntity();
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

        $middleware = new AuthorizationServerMiddleware($server);
        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                return func_get_args()[1];
            }
        );
        self::assertEquals(200, $response->getStatusCode());
    }

    public function testOAuthErrorResponse(): void
    {
        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepository->method('validateClient')->willReturn(false);

        $server = new AuthorizationServer(
            $clientRepository,
            $this->getMockBuilder(AccessTokenRepositoryInterface::class)->getMock(),
            $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock(),
            'file://' . __DIR__ . '/../Stubs/private.key',
            base64_encode(random_bytes(36)),
            new StubResponseType()
        );

        $server->enableGrantType(new ClientCredentialsGrant(), new DateInterval('PT1M'));

        $_POST['grant_type'] = 'client_credentials';
        $_POST['client_id'] = 'foo';
        $_POST['client_secret'] = 'bar';

        $request = ServerRequestFactory::fromGlobals();

        $middleware = new AuthorizationServerMiddleware($server);

        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                return func_get_args()[1];
            }
        );

        self::assertEquals(401, $response->getStatusCode());
    }

    public function testOAuthErrorResponseRedirectUri(): void
    {
        $exception = OAuthServerException::invalidScope('test', 'http://foo/bar');
        $response = $exception->generateHttpResponse(new Response());

        self::assertEquals(302, $response->getStatusCode());
        self::assertEquals(
            'http://foo/bar?error=invalid_scope&error_description=The+requested+scope+is+invalid%2C+unknown%2C+or+malformed&hint=Check+the+%60test%60+scope',
            $response->getHeader('location')[0]
        );
    }

    public function testOAuthErrorResponseRedirectUriFragment(): void
    {
        $exception = OAuthServerException::invalidScope('test', 'http://foo/bar');
        $response = $exception->generateHttpResponse(new Response(), true);

        self::assertEquals(302, $response->getStatusCode());
        self::assertEquals(
            'http://foo/bar#error=invalid_scope&error_description=The+requested+scope+is+invalid%2C+unknown%2C+or+malformed&hint=Check+the+%60test%60+scope',
            $response->getHeader('location')[0]
        );
    }

    public function testOAuthErrorResponseRedirectUriWithDelimiter()
    {
        $exception = OAuthServerException::invalidScope('test', 'http://foo/bar', '#');
        $response = $exception->generateHttpResponse(new Response());

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals(
            'http://foo/bar#error=invalid_scope&error_description=The+requested+scope+is+invalid%2C+unknown%2C+or+malformed&hint=Check+the+%60test%60+scope',
            $response->getHeader('location')[0]
        );
    }
}
