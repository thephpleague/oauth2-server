<?php
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

// Routing setup
$request = (new Request)->createFromGlobals();
$router = new \Orno\Route\RouteCollection;

$router->get('/tokeninfo', function (Request $request) use ($server) {

    $token = [
        'owner_id'  =>  $server->getOwnerId(),
        'owner_type'  =>  $server->getOwnerType(),
        'access_token'  =>  $server->getAccessToken(),
        'client_id'  =>  $server->getClientId(),
        'scopes'  =>  $server->getScopes()
    ];

    return new Response(json_encode($token));

});

$dispatcher = $router->getDispatcher();

try {

    // Check that access token is present
    $server->isValidRequest();

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
        'message'   =>  $e->getMessage()
    ]), $e->httpStatusCode);

    foreach ($e->getHttpHeaders() as $header) {
        $response->headers($header);
    }

} catch (\Exception $e) {

    $response = new Orno\Http\Response;
    $response->setStatusCode(500);
    $response->setContent(json_encode(['status_code' => 500, 'message' => $e->getMessage()]));

} finally {

    // Return the response
    $response->headers->set('Content-type', 'application/json');
    $response->send();

}