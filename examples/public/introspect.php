<?php

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use OAuth2ServerExamples\Repositories\ClientRepository;
use OAuth2ServerExamples\Repositories\ScopeRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\App;

include __DIR__ . '/../vendor/autoload.php';

$app = new App([
    // Add the authorization server to the DI container
    AuthorizationServer::class => function () {

        // Setup the authorization server
        $server = new AuthorizationServer(
            new ClientRepository(),                 // instance of ClientRepositoryInterface
            new AccessTokenRepository(),            // instance of AccessTokenRepositoryInterface
            new ScopeRepository(),                  // instance of ScopeRepositoryInterface
            'file://' . __DIR__ . '/../private.key',    // path to private key
            'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen'      // encryption key
        );

        return $server;
    },
]);

$app->post(
    '/introspect',
    function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {

        /* @var \League\OAuth2\Server\AuthorizationServer $server */
        $server = $app->getContainer()->get(AuthorizationServer::class);

        try {
            // Validate the given introspect request
            $server->validateIntrospectionRequest($request);

            // Try to respond to the introspection request
            return $server->respondToIntrospectionRequest($request, $response);
        } catch (OAuthServerException $exception) {

            // All instances of OAuthServerException can be converted to a PSR-7 response
            return $exception->generateHttpResponse($response);
        } catch (\Exception $exception) {

            // Catch unexpected exceptions
            $body = $response->getBody();
            $body->write($exception->getMessage());

            return $response->withStatus(500)->withBody($body);
        }
    }
);

$app->run();
