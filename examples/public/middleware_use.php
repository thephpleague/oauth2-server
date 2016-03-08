<?php

use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Middleware\AuthenticationServerMiddleware;
use League\OAuth2\Server\Middleware\ResourceServerMiddleware;
use League\OAuth2\Server\Server;
use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use OAuth2ServerExamples\Repositories\AuthCodeRepository;
use OAuth2ServerExamples\Repositories\ClientRepository;
use OAuth2ServerExamples\Repositories\RefreshTokenRepository;
use OAuth2ServerExamples\Repositories\ScopeRepository;
use OAuth2ServerExamples\Repositories\UserRepository;
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
        // Init our repositories
        $clientRepository = new ClientRepository();
        $accessTokenRepository = new AccessTokenRepository();
        $scopeRepository = new ScopeRepository();
        $authCodeRepository = new AuthCodeRepository();
        $refreshTokenRepository = new RefreshTokenRepository();
        $userRepository = new UserRepository();

        $privateKeyPath = 'file://' . __DIR__ . '/../private.key';
        $publicKeyPath = 'file://' . __DIR__ . '/../public.key';

        // Setup the authorization server
        $server = new Server(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $privateKeyPath,
            $publicKeyPath
        );

        // Enable the authentication code grant on the server with a token TTL of 1 hour
        $server->enableGrantType(
            new AuthCodeGrant(
                $authCodeRepository,
                $refreshTokenRepository,
                $userRepository,
                new \DateInterval('PT10M')
            ),
            new \DateInterval('PT1H')
        );

        // Enable the refresh token grant on the server with a token TTL of 1 month
        $server->enableGrantType(
            new RefreshTokenGrant($refreshTokenRepository),
            new \DateInterval('PT1M')
        );

        return $server;
    },
]);

// Access token issuer
$app->post('/access_token', function () {
})->add(new AuthenticationServerMiddleware($app->getContainer()->get(Server::class)));

// Secured API
$app->group('/api', function () {
    $this->get('/user', function (ServerRequestInterface $request, ResponseInterface $response) {
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

        $body = new Stream('php://temp', 'r+');
        $body->write(json_encode($params));

        return $response->withBody($body);
    });
})->add(new ResourceServerMiddleware($app->getContainer()->get(Server::class)));

$app->run();
