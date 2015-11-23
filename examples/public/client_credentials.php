<?php

namespace OAuth2ServerExamples;

use Exception;

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\ClientCredentialsGrant;
use League\OAuth2\Server\Server;

use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use OAuth2ServerExamples\Repositories\ClientRepository;
use OAuth2ServerExamples\Repositories\ScopeRepository;

use Slim\App;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

include(__DIR__ . '/../vendor/autoload.php');

// Setup the authorization server
$server = new Server();

// Enable the client credentials grant on the server
$server->enableGrantType(new ClientCredentialsGrant(
    new ClientRepository(),
    new ScopeRepository(),
    new AccessTokenRepository()
));

// App
$app = new App([Server::class => $server]);

$app->post('/access_token', function (ServerRequestInterface $request, ResponseInterface $response) {
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
