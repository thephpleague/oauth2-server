<?php

use League\OAuth2\Server\ResourceServer;
use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\App;

include __DIR__ . '/../vendor/autoload.php';

$app = new App([
    // Add the resource server to the DI container
    ResourceServer::class => function () {
        $server = new ResourceServer(
            new AccessTokenRepository(),            // instance of AccessTokenRepositoryInterface
            'file://' . __DIR__ . '/../public.key'  // the authorization server's public key
        );

        return $server;
    },
]);

// Add the resource server middleware which will intercept and validate requests
$app->add(
    new \League\OAuth2\Server\Middleware\ResourceServerMiddleware(
        $app->getContainer()->get(ResourceServer::class)
    )
);

// An example endpoint secured with OAuth 2.0
$app->get(
    '/users',
    function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {
        $users = [
            [
                'id'    => 123,
                'name'  => 'Alex',
                'email' => 'alex@thephpleague.com',
            ],
            [
                'id'    => 124,
                'name'  => 'Frank',
                'email' => 'frank@thephpleague.com',
            ],
            [
                'id'    => 125,
                'name'  => 'Phil',
                'email' => 'phil@thephpleague.com',
            ],
        ];

        $totalUsers = \count($users);

        // If the access token doesn't have the `basic` scope hide users' names
        if (\in_array('basic', $request->getAttribute('oauth_scopes')) === false) {
            for ($i = 0; $i < $totalUsers; $i++) {
                unset($users[$i]['name']);
            }
        }

        // If the access token doesn't have the `email` scope hide users' email addresses
        if (\in_array('email', $request->getAttribute('oauth_scopes')) === false) {
            for ($i = 0; $i < $totalUsers; $i++) {
                unset($users[$i]['email']);
            }
        }

        $response->getBody()->write(\json_encode($users));

        return $response->withStatus(200);
    }
);

$app->run();
