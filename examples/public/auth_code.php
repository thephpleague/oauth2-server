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

// Setup the authorization server
$server = new Server('file://' . __DIR__ . '/../private.key');

// Init our repositories
$userRepository = new UserRepository();
$clientRepository = new ClientRepository();
$scopeRepository = new ScopeRepository();
$accessTokenRepository = new AccessTokenRepository();
$refreshTokenRepository = new RefreshTokenRepository();

// Enable the client credentials grant on the server
$passwordGrant = new PasswordGrant(
    $userRepository,
    $clientRepository,
    $scopeRepository,
    $accessTokenRepository,
    $refreshTokenRepository
);
$server->enableGrantType($passwordGrant);

// App
$app = new App([Server::class => $server]);

$app->any('/authorise', function (Request $request, Response $response) {
     if (strtoupper($request->getMethod()) === 'GET') {
         $response = $response->withHeader('Set-Cookie', $authCodeGrant->storeOriginalRequestParams)
     }
});

$app->post('/access_token', function (Request $request, Response $response) {
    /** @var Server $server */
    $server = $this->get(Server::class);
    try {
        return $server->respondToRequest($request);
    } catch (OAuthServerException $e) {
        return $e->generateHttpResponse();
    } catch (\Exception $e) {
        return $response->withStatus(500)->write($e->getMessage());
    }
});

$app->run();
