<?php

use League\OAuth2\Server\Entity\EntityFactory;
use Orno\Http\Request;
use Orno\Http\Response;
use MongoDBExample\Document;
use MongoDBExample\Storage;

include __DIR__.'/vendor/autoload.php';

$dm = MongoDBExample\Config\DM::get();

// Routing setup
$request = (new Request())->createFromGlobals();
$router = new \Orno\Route\RouteCollection();
$router->setStrategy(\Orno\Route\RouteStrategyInterface::RESTFUL_STRATEGY);

// Set up the OAuth 2.0 authorization server
$server = new \League\OAuth2\Server\AuthorizationServer();
$server->setSessionStorage(new Storage\SessionStorage($dm));
$server->setAccessTokenStorage(new Storage\AccessTokenStorage($dm));
$server->setRefreshTokenStorage(new Storage\RefreshTokenStorage($dm));
$server->setClientStorage(new Storage\ClientStorage($dm));
$server->setScopeStorage(new Storage\ScopeStorage($dm));
$server->setAuthCodeStorage(new Storage\AuthCodeStorage($dm));

$entityFactory = new EntityFactory($server);

$clientCredentials = new \League\OAuth2\Server\Grant\ClientCredentialsGrant($entityFactory);
$server->addGrantType($clientCredentials);

$passwordGrant = new \League\OAuth2\Server\Grant\PasswordGrant($entityFactory);
$passwordGrant->setVerifyCredentialsCallback(function ($username, $password) use($dm) {

    $User = $dm->getRepository("MongoDBExample\Document\User")->find($username);
    if(!$User)
        return false;
        
    if (password_verify($password, $User->Password)) {
        return $username;
    }

    return false;
});
$server->addGrantType($passwordGrant);

$refrehTokenGrant = new \League\OAuth2\Server\Grant\RefreshTokenGrant($entityFactory);
$server->addGrantType($refrehTokenGrant);

// Routing setup
$request = (new Request())->createFromGlobals();
$router = new \Orno\Route\RouteCollection();

$router->post('/access_token', function (Request $request) use ($server) {

    try {
        $response = $server->issueAccessToken();

        return new Response(json_encode($response), 200);
    } catch (Exception $e) {
        return new Response(
            json_encode([
                'error'     =>  $e->errorType,
                'message'   =>  $e->getMessage(),
            ]),
            $e->httpStatusCode,
            $e->getHttpHeaders()
        );
    }

});

$dispatcher = $router->getDispatcher();

try {
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
} catch (Exception $e) {
    $response = new Orno\Http\Response();
    $response->setStatusCode(500);
    $response->setContent(json_encode(['status_code' => 500, 'message' => $e->getMessage()]));
} finally {
    // Return the response
    $response->headers->set('Content-type', 'application/json');
    $response->send();
}
