<?php

use League\OAuth2\Server\ResourceServer;
use Orno\Http\Exception\NotFoundException;
use Orno\Http\Request;
use Orno\Http\Response;
use RelationalExample\Model;
use RelationalExample\Storage;

include __DIR__.'/vendor/autoload.php';

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

// Routing setup
$request = (new Request())->createFromGlobals();
$router = new \Orno\Route\RouteCollection();

// GET /tokeninfo
$router->get('/tokeninfo', function (Request $request) use ($server) {

    $accessToken = $server->getAccessToken();
    $session = $server->getSessionStorage()->getByAccessToken($accessToken);
    $token = [
        'owner_id' => $session->getOwnerId(),
        'owner_type' => $session->getOwnerType(),
        'access_token' => $accessToken,
        'client_id' => $session->getClient()->getId(),
        'scopes' => $accessToken->getScopes(),
    ];

    return new Response(json_encode($token));

});

// GET /users
$router->get('/users', function (Request $request) use ($server) {

    $results = (new Model\Users())->get();

    $users = [];

    foreach ($results as $result) {
        $user = [
            'username'  =>  $result['username'],
            'name'      =>  $result['name'],
        ];

        if ($server->getAccessToken()->hasScope('email')) {
            $user['email'] = $result['email'];
        }

        if ($server->getAccessToken()->hasScope('photo')) {
            $user['photo'] = $result['photo'];
        }

        $users[] = $user;
    }

    return new Response(json_encode($users));
});

// GET /users/{username}
$router->get('/users/{username}', function (Request $request, Response $response, array $args) use ($server) {

    $result = (new Model\Users())->get($args['username']);

    if (count($result) === 0) {
        throw new NotFoundException();
    }

    $user = [
        'username'  =>  $result[0]['username'],
        'name'      =>  $result[0]['name'],
    ];

    if ($server->getAccessToken()->hasScope('email')) {
        $user['email'] = $result[0]['email'];
    }

    if ($server->getAccessToken()->hasScope('photo')) {
        $user['photo'] = $result[0]['photo'];
    }

    return new Response(json_encode($user));
});

$dispatcher = $router->getDispatcher();

try {
    // Check that access token is present
    $server->isValidRequest(false);

    // A successful response
    $response = $dispatcher->dispatch(
        $request->getMethod(),
        $request->getPathInfo()
    );
} catch (\Orno\Http\Exception $e) {
    // A failed response
    $response = $e->getJsonResponse();
    $response->setContent(json_encode(['status_code' => $e->getStatusCode(), 'message' => $e->getMessage()]));
} catch (\League\OAuth2\Server\Exception\OAuthException $e) {
    $response = new Response(json_encode([
        'error'     =>  $e->errorType,
        'message'   =>  $e->getMessage(),
    ]), $e->httpStatusCode);

    foreach ($e->getHttpHeaders() as $header) {
        $response->headers($header);
    }
} catch (\Exception $e) {
    $response = new Orno\Http\Response();
    $response->setStatusCode(500);
    $response->setContent(json_encode(['status_code' => 500, 'message' => $e->getMessage()]));
} finally {
    // Return the response
    $response->headers->set('Content-type', 'application/json');
    $response->send();
}
