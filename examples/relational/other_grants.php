<?php

namespace OAuth2Server\RelationalExample;

use \Orno\Http\Request;
use \Orno\Http\Response;
use \Orno\Http\JsonResponse;
use \Orno\Http\Exception\MethodNotAllowedException;

use Illuminate\Database\Capsule\Manager as Capsule;

// use \League\OAuth2\Server\Exception;
use \RelationalExample\Storage;
use \RelationalExample\Model;

include __DIR__.'/vendor/autoload.php';

// Routing setup
$router = new \Orno\Route\RouteCollection;

// Set up the OAuth 2.0 resource server
$server = new \League\OAuth2\Server\AuthorizationServer;
$server->setSessionStorage(new Storage\SessionStorage);
$server->setAccessTokenStorage(new Storage\AccessTokenStorage);
$server->setRefreshTokenStorage(new Storage\RefreshTokenStorage);
$server->setClientStorage(new Storage\ClientStorage);
$server->setScopeStorage(new Storage\ScopeStorage);
$server->setAuthCodeStorage(new Storage\AuthCodeStorage);

$clientCredentials = new \League\OAuth2\Server\Grant\ClientCredentialsGrant();
$server->addGrantType($clientCredentials);
$passwordGrant = new \League\OAuth2\Server\Grant\PasswordGrant();
$server->addGrantType($passwordGrant);
$refrehTokenGrant = new \League\OAuth2\Server\Grant\RefreshTokenGrant();
$server->addGrantType($refrehTokenGrant);

$request = (new Request)->createFromGlobals();
$server->setRequest($request);

$router->post('/access_token', function (Request $request) use ($server) {

    try {

        $response = $server->issueAccessToken();
        return new Response(json_encode($response), 200);

    } catch (\Exception $e) {

        return new Response(
            json_encode([
                'error'     =>  $e->errorType,
                'message'   =>  $e->getMessage()
            ]),
            $e->httpStatusCode,
            $e->getHttpHeaders()
        );

    }

});

$dispatcher = $router->getDispatcher();
$response = $dispatcher->dispatch($request->getMethod(), $request->getPathInfo());
$response->send();
