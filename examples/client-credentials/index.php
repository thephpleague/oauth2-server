<?php

use Symfony\Component\HttpFoundation\Request;

include (__DIR__.'/../vendor/autoload.php');

// Setup the authorization server
$server = new \League\OAuth2\Server\Server();
$server->addRepository(new \OAuth2ServerExamples\Repositories\ClientRepository());
$server->addRepository(new \OAuth2ServerExamples\Repositories\ScopeRepository());
$server->addRepository(new \OAuth2ServerExamples\Repositories\AccessTokenRepository());

// Enable the client credentials grant which will return access tokens that last for 24 hours
$server->enableGrantType('ClientCredentialsGrant', null, new \DateInterval('PT24H'));

// Setup the routing
$application = new \Proton\Application();
$application->post('/access_token', function (Request $request) use ($server) {
    return $server->getAccessTokenResponse($request);
});

// Run the app
$application->run();
