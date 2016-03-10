<?php

namespace LeagueTests\Middleware;

use League\OAuth2\Server\Middleware\ResourceServerMiddleware;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\Server;
use LeagueTests\Stubs\StubResponseType;
use Zend\Diactoros\Response;
use Zend\Diactoros\ServerRequest;

class ResourceServerMiddlewareTest extends \PHPUnit_Framework_TestCase
{
    public function testValidResponse()
    {
        $clientRepository = $this->getMock(ClientRepositoryInterface::class);

        $server = new Server(
            $clientRepository,
            $this->getMock(AccessTokenRepositoryInterface::class),
            $this->getMock(ScopeRepositoryInterface::class),
            '',
            '',
            new StubResponseType()
        );

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', 'Basic test');

        $middleware = new ResourceServerMiddleware($server);
        $response = $middleware->__invoke(
            $request,
            new Response(),
            function () {
                $this->assertEquals('test', func_get_args()[0]->getAttribute('oauth_access_token_id'));

                return func_get_args()[1];
            }
        );

        $this->assertEquals(200, $response->getStatusCode());
    }

    public function testErrorResponse()
    {
        $clientRepository = $this->getMock(ClientRepositoryInterface::class);

        $server = new Server(
            $clientRepository,
            $this->getMock(AccessTokenRepositoryInterface::class),
            $this->getMock(ScopeRepositoryInterface::class),
            '',
            '',
            new StubResponseType()
        );

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', '');

        $middleware = new ResourceServerMiddleware($server);
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
