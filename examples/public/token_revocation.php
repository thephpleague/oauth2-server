<?php

declare(strict_types=1);

include __DIR__ . '/../vendor/autoload.php';

use Laminas\Diactoros\Stream;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\TokenServer;
use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use OAuth2ServerExamples\Repositories\ClientRepository;
use OAuth2ServerExamples\Repositories\RefreshTokenRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\App;

$app = new App([
    'settings' => [
        'displayErrorDetails' => true,
    ],
    TokenServer::class => function () {
        // Init our repositories
        $clientRepository = new ClientRepository();
        $accessTokenRepository = new AccessTokenRepository();
        $refreshTokenRepository = new RefreshTokenRepository();

        $publicKeyPath = 'file://' . __DIR__ . '/../public.key';

        // Setup the authorization server
        return new TokenServer(
            $clientRepository,
            $accessTokenRepository,
            $refreshTokenRepository,
            $publicKeyPath,
            'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen'
        );
    },
]);

$app->post('/revoke_token', function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {
    /* @var \League\OAuth2\Server\TokenServer $server */
    $server = $app->getContainer()->get(TokenServer::class);

    try {
        return $server->respondToTokenRevocationRequest($request, $response);
    } catch (OAuthServerException $exception) {
        return $exception->generateHttpResponse($response);
    } catch (Exception $exception) {
        $body = new Stream('php://temp', 'r+');
        $body->write($exception->getMessage());

        return $response->withStatus(500)->withBody($body);
    }
});

$app->run();
