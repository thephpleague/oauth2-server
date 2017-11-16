<?php

namespace LeagueTests\Middleware;

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
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequestFactory;

class AuthorizationServerMiddlewareTest extends TestCase
{
    const DEFAULT_SCOPE = 'basic';

    public function testValidResponse()
    {
        $clientRepository = $this->getMockBuilder(ClientRepositoryInterface::class)->getMock();
        $clientRepository->method('getClientEntity')->willReturn(new ClientEntity());

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

        $middleware = new AuthorizationServerMiddleware($server);
        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                return func_get_args()[1];
            }
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

        $middleware = new AuthorizationServerMiddleware($server);

        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                return func_get_args()[1];
            }
        );

        $this->assertEquals(401, $response->getStatusCode());
    }

    public function testOAuthErrorResponseRedirectUri()
    {
        $exception = OAuthServerException::invalidScope('test', 'http://foo/bar');
        $response = $exception->generateHttpResponse(new Response());

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('http://foo/bar?error=invalid_scope&message=The+requested+scope+is+invalid%2C+unknown%2C+or+malformed&hint=Check+the+%60test%60+scope',
            $response->getHeader('location')[0]);
    }

    public function testOAuthErrorResponseRedirectUriFragment()
    {
        $exception = OAuthServerException::invalidScope('test', 'http://foo/bar');
        $response = $exception->generateHttpResponse(new Response(), true);

        $this->assertEquals(302, $response->getStatusCode());
        $this->assertEquals('http://foo/bar#error=invalid_scope&message=The+requested+scope+is+invalid%2C+unknown%2C+or+malformed&hint=Check+the+%60test%60+scope',
            $response->getHeader('location')[0]);
    }
}
