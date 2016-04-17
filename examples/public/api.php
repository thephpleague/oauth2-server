<?php

use League\OAuth2\Server\ResourceServer;
use League\OAuth2\Server\Server;
use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\App;

include __DIR__ . '/../vendor/autoload.php';

$app = new App([
    'settings'    => [
        'displayErrorDetails' => true,
    ],
    Server::class => function () {
        // Setup the authorization server
        $server = new ResourceServer(
            new AccessTokenRepository(),
            'file://' . __DIR__ . '/../public.key'
        );

        return $server;
    },
]);

$app->add(
    new \League\OAuth2\Server\Middleware\ResourceServerMiddleware(
        $app->getContainer()->get(Server::class)
    )
);

$app->get('/users', function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {

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

    // If the access token doesn't have the `basic` scope hide users' names
    if (in_array('basic', $request->getAttribute('oauth_scopes')) === false) {
        for ($i = 0; $i < count($users); $i++) {
            unset($users[$i]['name']);
        }
    }

    // If the access token doesn't have the `emal` scope hide users' email addresses
    if (in_array('email', $request->getAttribute('oauth_scopes')) === false) {
        for ($i = 0; $i < count($users); $i++) {
            unset($users[$i]['email']);
        }
    }

    $response->getBody()->write(json_encode($users));

    return $response->withStatus(200);
});

$app->run();
