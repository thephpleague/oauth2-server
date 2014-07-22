<?php

namespace OAuth2Server\RelationalExample;

use \Orno\Http\Request;
use \Orno\Http\Response;
use \Orno\Http\JsonResponse;
use \Orno\Http\Exception\NotFoundException;
use \League\OAuth2\Server\ResourceServer;
use \RelationalExample\Storage;
use \RelationalExample\Model;
use Illuminate\Database\Capsule\Manager as Capsule;
use \League\Event\Emitter;

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

$server = new ResourceServer(
    $sessionStorage,
    $accessTokenStorage,
    $clientStorage,
    $scopeStorage
);

$server->setRequest($request);

// Check that access token is present
try {
    $server->isValidRequest(false);
} catch (\League\OAuth2\Server\Exception\OAuthException $e) {

    foreach ($e->getHttpHeaders() as $header) {
        header($header);
    }

    echo json_encode([
        'error'     =>  $e->errorType,
        'message'   =>  $e->getMessage()
    ]);

    exit;
}

// GET /tokeninfo
$router->get('/tokeninfo', function (Request $request) use ($server) {

    $token = [
        'owner_id'  =>  $server->getOwnerId(),
        'owner_type'  =>  $server->getOwnerType(),
        'access_token'  =>  $server->getAccessToken(),
        'client_id'  =>  $server->getClientId(),
        'scopes'  =>  $server->getScopes()
    ];

    return new JsonResponse($token);

});

// GET /users
$router->get('/users', function (Request $request) use ($server) {

    $results = (new Model\Users())->get();

    $users = [];

    foreach ($results as $result) {
        $user = [
            'username'  =>  $result['username'],
            'name'      =>  $result['name']
        ];

        if ($server->hasScope('email')) {
            $user['email'] = $result['email'];
        }

        if ($server->hasScope('photo')) {
            $user['photo'] = $result['photo'];
        }

        $users[] = $user;
    }

    return new JsonResponse($users);
});

// GET /users/{username}
$router->get('/users/{username}', function (Request $request, $args) use ($server) {

    $result = (new Model\Users())->get($args['username']);

    if (count($result) === 0) {
        throw new NotFoundException();
    }

    $user = [
        'username'  =>  $result[0]['username'],
        'name'      =>  $result[0]['name']
    ];

    if ($server->hasScope('email')) {
        $user['email'] = $result[0]['email'];
    }

    if ($server->hasScope('photo')) {
        $user['photo'] = $result[0]['photo'];
    }

    return new JsonResponse($user);
});

$dispatcher = $router->getDispatcher();
$response = $dispatcher->dispatch($request->getMethod(), $request->getPathInfo());
$response->send();
