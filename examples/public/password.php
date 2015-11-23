<?php

namespace OAuth2ServerExamples;

use Exception;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\PasswordGrant;
use League\OAuth2\Server\Server;

use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use OAuth2ServerExamples\Repositories\ClientRepository;
use OAuth2ServerExamples\Repositories\ScopeRepository;
use OAuth2ServerExamples\Repositories\UserRepository;

use Slim\App;
use Slim\Http\Request;
use Slim\Http\Response;

include(__DIR__ . '/../vendor/autoload.php');

// Setup the authorization server
$server = new Server();

// Enable the client credentials grant on the server
$server->enableGrantType(new PasswordGrant(
    new UserRepository(),
    new ClientRepository(),
    new ScopeRepository(),
    new AccessTokenRepository()
));

// App
$app = new App([Server::class => $server]);

$app->post('/access_token', function (Request $request, Response $response) {
    /** @var Server $server */
    $server = $this->getContainer()->get(Server::class);
    try {
        return $server->handleTokenRequest($request, $response);
    } catch (OAuthServerException $e) {
        return $e->getResponse($response);
    } catch (Exception $e) {
        return $response->withStatus(500)->write($e->getMessage());
    }
});

$app->run();
