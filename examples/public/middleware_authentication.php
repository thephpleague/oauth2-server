<?php

use League\OAuth2\Server\Grant\PasswordGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Middleware\AuthenticationServerMiddleware;
use League\OAuth2\Server\Server;
use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use OAuth2ServerExamples\Repositories\ClientRepository;
use OAuth2ServerExamples\Repositories\RefreshTokenRepository;
use OAuth2ServerExamples\Repositories\ScopeRepository;
use OAuth2ServerExamples\Repositories\UserRepository;
use Slim\App;

include __DIR__.'/../vendor/autoload.php';

// App
$app = new App([
    'settings'    => [
        'displayErrorDetails' => true,
    ],
    Server::class => function () {

        // Init our repositories
        $clientRepository = new ClientRepository();
        $accessTokenRepository = new AccessTokenRepository();
        $scopeRepository = new ScopeRepository();
        $userRepository = new UserRepository();
        $refreshTokenRepository = new RefreshTokenRepository();

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

        // Enable the grants
        $server->enableGrantType(
            new PasswordGrant($userRepository, $refreshTokenRepository),
            new \DateInterval('PT1H')
        );
        $server->enableGrantType(
            new RefreshTokenGrant($refreshTokenRepository),
            new \DateInterval('PT1H')
        );

        return $server;
    },
]);

$app->post('/access_token', function () {
})->add(new AuthenticationServerMiddleware($app->getContainer()->get(Server::class)));

$app->run();
