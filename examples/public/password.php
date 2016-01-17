<?php

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\PasswordGrant;
use League\OAuth2\Server\Server;

use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use OAuth2ServerExamples\Repositories\ClientRepository;
use OAuth2ServerExamples\Repositories\RefreshTokenRepository;
use OAuth2ServerExamples\Repositories\ScopeRepository;
use OAuth2ServerExamples\Repositories\UserRepository;

use Slim\App;
use Slim\Http\Request;
use Slim\Http\Response;

include(__DIR__ . '/../vendor/autoload.php');

// App
$app = new App([
    Server::class => function () {

        // Init our repositories
        $clientRepository = new ClientRepository();
        $scopeRepository = new ScopeRepository();
        $accessTokenRepository = new AccessTokenRepository();
        $userRepository = new UserRepository();
        $refreshTokenRepository = new RefreshTokenRepository();

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

        // Enable the client credentials grant on the server with a token TTL of 1 hour
        $server->enableGrantType(
            new PasswordGrant($userRepository, $refreshTokenRepository),
            new \DateInterval('PT1H')
        );

        return $server;
    }
]);

$app->post('/access_token', function (Request $request, Response $response) {
    /** @var Server $server */
    $server = $this->get(Server::class);
    try {
        return $server->respondToRequest($request, $response);
    } catch (OAuthServerException $e) {
        return $e->generateHttpResponse($response);
    } catch (\Exception $e) {
        return $response->withStatus(500)->write($e->getMessage());
    }
});

$app->run();
