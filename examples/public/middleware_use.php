<?php
/**
 * @author      Alex Bilbie <hello@alexbilbie.com>
 * @copyright   Copyright (c) Alex Bilbie
 * @license     http://mit-license.org/
 *
 * @link        https://github.com/thephpleague/oauth2-server
 */

use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Middleware\AuthorizationServerMiddleware;
use League\OAuth2\Server\Middleware\ResourceServerMiddleware;
use League\OAuth2\Server\ResourceServer;
use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use OAuth2ServerExamples\Repositories\AuthCodeRepository;
use OAuth2ServerExamples\Repositories\ClientRepository;
use OAuth2ServerExamples\Repositories\RefreshTokenRepository;
use OAuth2ServerExamples\Repositories\ScopeRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\App;
use Zend\Diactoros\Stream;

include __DIR__ . '/../vendor/autoload.php';

$app = new App([
    'settings'                 => [
        'displayErrorDetails' => true,
    ],
    AuthorizationServer::class => function () {
        // Init our repositories
        $clientRepository = new ClientRepository();
        $accessTokenRepository = new AccessTokenRepository();
        $scopeRepository = new ScopeRepository();
        $authCodeRepository = new AuthCodeRepository();
        $refreshTokenRepository = new RefreshTokenRepository();

        $privateKeyPath = 'file://' . __DIR__ . '/../private.key';

        // Setup the authorization server
        $server = new AuthorizationServer(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $privateKeyPath,
            'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen'
        );

        // Enable the authentication code grant on the server with a token TTL of 1 hour
        $server->enableGrantType(
            new AuthCodeGrant(
                $authCodeRepository,
                $refreshTokenRepository,
                new \DateInterval('PT10M')
            ),
            new \DateInterval('PT1H')
        );

        // Enable the refresh token grant on the server with a token TTL of 1 month
        $server->enableGrantType(
            new RefreshTokenGrant($refreshTokenRepository),
            new \DateInterval('P1M')
        );

        return $server;
    },
    ResourceServer::class => function () {
        $publicKeyPath = 'file://' . __DIR__ . '/../public.key';

        $server = new ResourceServer(
            new AccessTokenRepository(),
            $publicKeyPath
        );

        return $server;
    },
]);

// Access token issuer
$app->post('/access_token', function () {
})->add(new AuthorizationServerMiddleware($app->getContainer()->get(AuthorizationServer::class)));

// Secured API
$app->group('/api', function () {
    $this->get('/user', function (ServerRequestInterface $request, ResponseInterface $response) {
        $params = [];

        if (\in_array('basic', $request->getAttribute('oauth_scopes', []))) {
            $params = [
                'id'   => 1,
                'name' => 'Alex',
                'city' => 'London',
            ];
        }

        if (\in_array('email', $request->getAttribute('oauth_scopes', []))) {
            $params['email'] = 'alex@example.com';
        }

        $body = new Stream('php://temp', 'r+');
        $body->write(\json_encode($params));

        return $response->withBody($body);
    });
})->add(new ResourceServerMiddleware($app->getContainer()->get(ResourceServer::class)));

$app->run();
