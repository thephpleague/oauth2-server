<?php

use Laminas\Diactoros\Response;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\IntrospectionServer;
use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\App;

include __DIR__ . '/../vendor/autoload.php';

$app = new App([
    // Add the authorization server to the DI container
    IntrospectionServer::class => function () {

        // Setup the authorization server
        $server = new IntrospectionServer(
            new AccessTokenRepository(),
            'file://' . __DIR__ . '/../public.key'
        );

        return $server;
    },
]);

$app->post(
    '/introspect',
    function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {
        /* @var IntrospectionServer $server */
        $server = $app->getContainer()->get(IntrospectionServer::class);

        try {
            // Try to respond to the introspection request
            return $server->respondToIntrospectionRequest($request, new Response());
        } catch (OAuthServerException $exception) {

            // All instances of OAuthServerException can be converted to a PSR-7 response
            return $exception->generateHttpResponse($response);
        } catch (Exception $exception) {

            // Catch unexpected exceptions
            $body = $response->getBody();
            $body->write($exception->getMessage());

            return $response->withStatus(500)->withBody($body);
        }
    }
);

$app->run();
