<?php

namespace OAuth2Server\RelationalExample;

use \Orno\Http\Request;
use \Orno\Http\Response;
use \Orno\Http\JsonResponse;
use \League\OAuth2\Server\AuthorizationServer;
use \League\OAuth2\Server\Exception;
use \League\OAuth2\Server\Grant;
use \RelationalExample\Storage;
use \RelationalExample\Model;
use Illuminate\Database\Capsule\Manager as Capsule;

include __DIR__.'/vendor/autoload.php';

// Routing setup
$request = (new Request)->createFromGlobals();
$router = new \Orno\Route\RouteCollection;
$router->setStrategy(\Orno\Route\RouteStrategyInterface::RESTFUL_STRATEGY);

// Set up the OAuth 2.0 resource server
$sessionStorage = new Storage\SessionStorage();
$accessTokenStorage = new Storage\AccessTokenStorage();
$clientStorage = new Storage\ClientStorage();
$scopeStorage = new Storage\ScopeStorage();
$accessTokenStorage = new Storage\AccessTokenStorage();
$refreshTokenStorage = new Storage\RefreshTokenStorage();
$authCodeStorage = new Storage\AuthCodeStorage();

$server = new AuthorizationServer();
$server->setSessionStorage($sessionStorage);
$server->setAccessTokenStorage($accessTokenStorage);
$server->setRefreshTokenStorage($refreshTokenStorage);
$server->setClientStorage($clientStorage);
$server->setScopeStorage($scopeStorage);
$server->setAuthCodeStorage($authCodeStorage);

$authCodeGrant = new Grant\AuthCodeGrant();
$server->addGrantType($authCodeGrant);

$server->setRequest($request);

// GET /authorize
$router->get('/authorize', function (Request $request) use ($server) {

    // First ensure the parameters in the query string are correct

    try {
        $authParams = $server->getGrantType('authorization_code')->checkAuthorizeParams();
    } catch (\Exception $e) {
        echo json_encode([
            'error'     =>  $e->errorType,
            'message'   =>  $e->getMessage()
        ]);

        exit;
    }

    // Normally at this point you would show the user a sign-in screen and ask them to authorize the requested scopes

    // ...

    // Create a new authorize request which will respond with a redirect URI that the user will be redirected to

    $redirectUri = $server->newAuthorizeRequest('user', 1, $authParams);

    $response = new Response('', 200, [
        'Location'  =>  $redirectUri
    ]);

    return $response;
});

$dispatcher = $router->getDispatcher();
$response = $dispatcher->dispatch($request->getMethod(), $request->getPathInfo());
$response->send();

// var_dump(Capsule::getQueryLog());
