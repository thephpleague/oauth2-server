<?php

namespace LeagueTests\Middleware;

use Lcobucci\JWT\Builder;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Jwt\AccessTokenConverter;
use League\OAuth2\Server\Jwt\BearerTokenValidator;
use League\OAuth2\Server\Middleware\AuthenticationServerMiddleware;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseFactory;
use League\OAuth2\Server\Server;
use League\OAuth2\Server\TemplateRenderer\RendererInterface;
use LeagueTests\Stubs\ClientEntity;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequestFactory;

class AuthenticationServerMiddlewareTest extends \PHPUnit_Framework_TestCase
{
    public function testValidResponse()
    {
        $clientRepository = $this->getMock(ClientRepositoryInterface::class);
        $clientRepository->method('getClientEntity')->willReturn(new ClientEntity());

        $scopeRepositoryMock = $this->getMockBuilder(ScopeRepositoryInterface::class)->getMock();
        $scopeRepositoryMock->method('finalizeScopes')->willReturnArgument(0);

        $server = new Server(
            $clientRepository,
            $this->getMock(AccessTokenRepositoryInterface::class),
            $scopeRepositoryMock,
            new BearerTokenValidator(
                $this->getMock(AccessTokenRepositoryInterface::class),
                'file://' . __DIR__ . '/../Stubs/public.key'
            )
        );

        $server->enableGrantType(
            new ClientCredentialsGrant(
                new ResponseFactory(
                    new AccessTokenConverter(new Builder(), 'file://' . __DIR__ . '/../Stubs/private.key'),
                    $this->getMock(RendererInterface::class)
                )
            ),
            new \DateInterval('PT1M')
        );

        $_POST['grant_type'] = 'client_credentials';
        $_POST['client_id'] = 'foo';
        $_POST['client_secret'] = 'bar';

        $request = ServerRequestFactory::fromGlobals();

        $middleware = new AuthenticationServerMiddleware($server);
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
        $clientRepository = $this->getMock(ClientRepositoryInterface::class);
        $clientRepository->method('getClientEntity')->willReturn(null);

        $server = new Server(
            $clientRepository,
            $this->getMock(AccessTokenRepositoryInterface::class),
            $this->getMock(ScopeRepositoryInterface::class),
            new BearerTokenValidator(
                $this->getMock(AccessTokenRepositoryInterface::class),
                'file://' . __DIR__ . '/../Stubs/public.key'
            )
        );

        $server->enableGrantType(
            new ClientCredentialsGrant(
                new ResponseFactory(
                    new AccessTokenConverter(new Builder(), 'file://' . __DIR__ . '/../Stubs/private.key'),
                    $this->getMock(RendererInterface::class)
                )
            ),
            new \DateInterval('PT1M')
        );

        $_POST['grant_type'] = 'client_credentials';
        $_POST['client_id'] = 'foo';
        $_POST['client_secret'] = 'bar';

        $request = ServerRequestFactory::fromGlobals();

        $middleware = new AuthenticationServerMiddleware($server);

        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                return func_get_args()[1];
            }
        );

        $this->assertEquals(401, $response->getStatusCode());
    }
}
