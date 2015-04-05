<?php

use League\OAuth2\Server\Exception\OAuthException;
use League\OAuth2\Server\Server;
use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use OAuth2ServerExamples\Repositories\ClientRepository;
use OAuth2ServerExamples\Repositories\ScopeRepository;
use Symfony\Component\HttpFoundation\Request;

include(__DIR__ . '/../vendor/autoload.php');

// Setup the authorization server
$server = new Server();
$server->addRepository(new ClientRepository());
$server->addRepository(new ScopeRepository());
$server->addRepository(new AccessTokenRepository());

// Enable the client credentials grant which will return access tokens that last for 24 hours
$server->enableGrantType('ClientCredentialsGrant', null, new \DateInterval('PT24H'));

// Setup app + routing
$application = new \Proton\Application();
$application->post('/access_token', function (Request $request) use ($server) {
    try {
        return $server->getAccessTokenResponse($request);
    } catch (OAuthException $e) {
        return $e->generateHttpResponse();
    }
});

// Run the app
$application->run();
