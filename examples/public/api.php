<?php

use League\OAuth2\Server\Server;
use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use OAuth2ServerExamples\Repositories\ClientRepository;
use OAuth2ServerExamples\Repositories\ScopeRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\App;
use Zend\Diactoros\Stream;

include __DIR__ . '/../vendor/autoload.php';

$app = new App([
    'settings'    => [
        'displayErrorDetails' => true,
    ],
    Server::class => function () {
        // Setup the authorization server
        $server = new Server(
            new ClientRepository(),
            new AccessTokenRepository(),
            new ScopeRepository(),
            'file://' . __DIR__ . '/../private.key',
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

    if (in_array('basic', $request->getAttribute('oauth_scopes')) === false) {
        for ($i = 0; $i < count($users); $i++) {
            unset($users[$i]['name']);
        }
    }

    if (in_array('email', $request->getAttribute('oauth_scopes')) === false) {
        for ($i = 0; $i < count($users); $i++) {
            unset($users[$i]['email']);
        }
    }

    $response->getBody()->write(json_encode($users));

    return $response->withStatus(200);
});

$app->run();
