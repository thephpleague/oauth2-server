<?php

namespace LeagueTests\Middleware;

use Lcobucci\JWT\Builder;
use League\OAuth2\Server\AccessTokenToJwtConverter;
use League\OAuth2\Server\Entities\AccessTokenEntity;
use League\OAuth2\Server\Middleware\ResourceServerMiddleware;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseFactory;
use League\OAuth2\Server\Server;
use LeagueTests\Stubs\ClientEntity;
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
            'file://' . __DIR__ . '/../Stubs/private.key',
            'file://' . __DIR__ . '/../Stubs/public.key',
            new ResponseFactory(__DIR__ . '/../Stubs/private.key', __DIR__ . '/../Stubs/public.key')
        );

        $client = new ClientEntity();
        $client->setIdentifier('clientName');

        $accessToken = new AccessTokenEntity();
        $accessToken->setIdentifier('test');
        $accessToken->setUserIdentifier(123);
        $accessToken->setExpiryDateTime((new \DateTime())->add(new \DateInterval('PT1H')));
        $accessToken->setClient($client);

        $converter = new AccessTokenToJwtConverter(new Builder(), 'file://' . __DIR__ . '/../Stubs/private.key');
        $token = $converter->convert($accessToken);

        $request = new ServerRequest();
        $request = $request->withHeader('authorization', sprintf('Bearer %s', $token));

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
            new ResponseFactory(__DIR__ . '/Stubs/private.key', __DIR__ . '/Stubs/public.key')
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
