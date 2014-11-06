---
layout: default
title: Authorization server with resource owner password credentials grant
permalink: /authorization-server/resource-owner-password-credentials-grant/
---

# Authorization server with resource owner password credentials grant

## Setup

Wherever you intialise your objects, initialize a new instance of the authorization server and bind the storage interfaces and authorization code grant:

~~~ php
$server = new \League\OAuth2\Server\AuthorizationServer;

$server->setSessionStorage(new Storage\SessionStorage);
$server->setAccessTokenStorage(new Storage\AccessTokenStorage);
$server->setClientStorage(new Storage\ClientStorage);
$server->setScopeStorage(new Storage\ScopeStorage);

$passwordGrant = new \League\OAuth2\Server\Grant\PasswordGrant();
$passwordGrant->setVerifyCredentialsCallback(function ($username, $password) {
    // implement logic here to validate a username and password, return an ID if valid, otherwise return false
});

$server->addGrantType($passwordGrant);
~~~


## Implementation

The client will request an access token so create an `/access_token` endpoint.

~~~ php
$router->post('/access_token', function (Request $request) use ($server) {

    try {

        $response = $server->issueAccessToken();
        return new Response(
            json_encode($response),
            200,
            [
                'Content-type'  =>  'application/json',
                'Cache-Control' =>  'no-store',
                'Pragma'        =>  'no-store'
            ]
        );

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
~~~
