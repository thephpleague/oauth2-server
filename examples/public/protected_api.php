<?php

use League\OAuth2\Server\Middleware\ResourceServerMiddleware;
use League\OAuth2\Server\Server;
use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use OAuth2ServerExamples\Repositories\ClientRepository;
use OAuth2ServerExamples\Repositories\ScopeRepository;
use Slim\App;
use Slim\Http\Request;
use Slim\Http\Response;

include __DIR__.'/../vendor/autoload.php';

// App
$app = new App([
    'settings'    => [
        'displayErrorDetails' => true,
    ],
    Server::class => function () {

        // Init our repositories
        $clientRepository = new ClientRepository();
        $scopeRepository = new ScopeRepository();
        $accessTokenRepository = new AccessTokenRepository();

        $privateKeyPath = 'file://'.__DIR__.'/../private.key';
        $publicKeyPath = 'file://'.__DIR__.'/../public.key';

        // Setup the authorization server
        $server = new Server(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $privateKeyPath,
            $publicKeyPath
        );

        return $server;
    },
]);

$app->add(new ResourceServerMiddleware($app->getContainer()->get(Server::class)));
$app->post('/api/example', function (Request $request, Response $response) {

    $params = [];

    if (in_array('basic', $request->getAttribute('oauth_scopes', []))) {
        $params = [
            'id'   => 1,
            'name' => 'Alex',
            'city' => 'London',
        ];
    }

    if (in_array('email', $request->getAttribute('oauth_scopes', []))) {
        $params['email'] = 'alex@example.com';
    }

    $response->getBody()->write(json_encode($params));

    return $response;
});

$app->run();
