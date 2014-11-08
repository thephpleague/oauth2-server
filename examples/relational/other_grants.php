<?php

use Orno\Http\Request;
use Orno\Http\Response;
use RelationalExample\Model;
use RelationalExample\Storage;

include __DIR__.'/vendor/autoload.php';

// Routing setup
$request = (new Request())->createFromGlobals();
$router = new \Orno\Route\RouteCollection();
$router->setStrategy(\Orno\Route\RouteStrategyInterface::RESTFUL_STRATEGY);

// Set up the OAuth 2.0 authorization server
$server = new \League\OAuth2\Server\AuthorizationServer();
$server->setSessionStorage(new Storage\SessionStorage());
$server->setAccessTokenStorage(new Storage\AccessTokenStorage());
$server->setRefreshTokenStorage(new Storage\RefreshTokenStorage());
$server->setClientStorage(new Storage\ClientStorage());
$server->setScopeStorage(new Storage\ScopeStorage());
$server->setAuthCodeStorage(new Storage\AuthCodeStorage());

$clientCredentials = new \League\OAuth2\Server\Grant\ClientCredentialsGrant();
$server->addGrantType($clientCredentials);

$passwordGrant = new \League\OAuth2\Server\Grant\PasswordGrant();
$passwordGrant->setVerifyCredentialsCallback(function ($username, $password) {
    $result = (new Model\Users())->get($username);
    if (count($result) !== 1) {
        return false;
    }

    if (password_verify($password, $result[0]['password'])) {
        return $username;
    }

    return false;
});
$server->addGrantType($passwordGrant);

$refrehTokenGrant = new \League\OAuth2\Server\Grant\RefreshTokenGrant();
$server->addGrantType($refrehTokenGrant);

// Routing setup
$request = (new Request())->createFromGlobals();
$router = new \Orno\Route\RouteCollection();

$router->post('/access_token', function (Request $request) use ($server) {

    try {
        $response = $server->issueAccessToken();

        return new Response(json_encode($response), 200);
    } catch (\Exception $e) {
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
} catch (\Exception $e) {
    $response = new Orno\Http\Response();
    $response->setStatusCode(500);
    $response->setContent(json_encode(['status_code' => 500, 'message' => $e->getMessage()]));
} finally {
    // Return the response
    $response->headers->set('Content-type', 'application/json');
    $response->send();
}
