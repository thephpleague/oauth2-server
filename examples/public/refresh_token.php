<?php

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
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

// Setup the authorization server
$server = new Server('file://' . __DIR__ . '/../private.key');

// Init our repositories
$userRepository = new UserRepository();
$clientRepository = new ClientRepository();
$scopeRepository = new ScopeRepository();
$accessTokenRepository = new AccessTokenRepository();
$refreshTokenRepository = new RefreshTokenRepository();

// Enable the client credentials grant on the server
$refreshTokenGrant = new RefreshTokenGrant(
    'file://' . __DIR__ . '/../public.key',
    $clientRepository,
    $scopeRepository,
    $accessTokenRepository,
    $refreshTokenRepository
);
$server->enableGrantType($refreshTokenGrant);

// App
$app = new App([Server::class => $server]);

$app->post('/access_token', function (Request $request, Response $response) {
    /** @var Server $server */
    $server = $this->get(Server::class);
    try {
        return $server->respondToRequest($request);
    } catch (OAuthServerException $e) {
        return $e->generateHttpResponse();
    } catch (\Exception $e) {
        return $response->withStatus(500)->write(
            sprintf('<h1>%s</h1><p>%s</p>', get_class($e), $e->getMessage())
        );
    }
});

$app->run();
