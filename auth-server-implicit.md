---
layout: default
title: Implicit grant
permalink: /authorization-server/implicit-grant/
---

# Implicit grant

__It is no longer best practice to use the Implicit Grant__. This grant is documented here for legacy purposes only. Industry best practice recommends using the Authorization Code Grant without a client secret for native and browser-based apps.

The implicit grant is similar to the authorization code grant with two distinct differences.

It is intended to be used for user-agent-based clients (e.g. single page web apps) that can't keep a client secret because all of the application code and storage is easily accessible.

Secondly instead of the authorization server returning an authorization code which is exchanged for an access token, the authorization server returns an access token.

## Flow

The client will redirect the user to the authorization server with the following parameters in the query string:

* `response_type` with the value `token`
* `client_id` with the client identifier
* `redirect_uri` with the client redirect URI. This parameter is optional, but if not sent the user will be redirected to a pre-registered redirect URI.
* `scope` a space delimited list of scopes
* `state` with a [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) token. This parameter is optional but highly recommended. You should store the value of the CSRF token in the user's session to be validated when they return.

All of these parameters will be validated by the authorization server.

The user will then be asked to login to the authorization server and approve the client.

If the user approves the client they will be redirected back to the authorization server with the following parameters in the query string:

* `token_type` with the value `Bearer`
* `expires_in` with an integer representing the TTL of the access token
* `access_token` a JWT signed with the authorization server's private key
* `state` with the state parameter sent in the original request. You should compare this value with the value stored in the user's session to ensure the authorization code obtained is in response to requests made by this client rather than another client application.

****Note**** this grant does <u>not</u> return a refresh token.

## Setup

Wherever you initialize your objects, initialize a new instance of the authorization server and bind the storage interfaces and authorization code grant:

~~~ php
// Init our repositories
$clientRepository = new ClientRepository(); // instance of ClientRepositoryInterface
$scopeRepository = new ScopeRepository(); // instance of ScopeRepositoryInterface
$accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface
$authCodeRepository = new AuthCodeRepository(); // instance of AuthCodeRepositoryInterface

$privateKey = 'file://path/to/private.key';
//$privateKey = new CryptKey('file://path/to/private.key', 'passphrase'); // if private key has a pass phrase
$encryptionKey = 'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen'; // generate using base64_encode(random_bytes(32))

// Setup the authorization server
$server = new \League\OAuth2\Server\AuthorizationServer(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKey,
    $encryptionKey
);

// Enable the implicit grant on the server
$server->enableGrantType(
    new ImplicitGrant(new \DateInterval('PT1H')),
    new \DateInterval('PT1H') // access tokens will expire after 1 hour
);
~~~

## Implementation

_Please note: These examples here demonstrate usage with the Slim Framework; Slim is not a requirement to use this library, you just need something that generates PSR7-compatible HTTP requests and responses._

The client will redirect the user to an authorization endpoint.

~~~ php
$app->get('/authorize', function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {

    /* @var \League\OAuth2\Server\AuthorizationServer $server */
    $server = $app->getContainer()->get(AuthorizationServer::class);

    try {

        // Validate the HTTP request and return an AuthorizationRequest object.
        $authRequest = $server->validateAuthorizationRequest($request);
        
        // The auth request object can be serialized and saved into a user's session.
        // You will probably want to redirect the user at this point to a login endpoint.
        
        // Once the user has logged in set the user on the AuthorizationRequest
        $authRequest->setUser(new UserEntity()); // an instance of UserEntityInterface
         
        // At this point you should redirect the user to an authorization page.
        // This form will ask the user to approve the client and the scopes requested.
        
        // Once the user has approved or denied the client update the status
        // (true = approved, false = denied)
        $authRequest->setAuthorizationApproved(true);
        
        // Return the HTTP redirect response
        return $server->completeAuthorizationRequest($authRequest, $response);
        
    } catch (OAuthServerException $exception) {
        
        // All instances of OAuthServerException can be formatted into a HTTP response
        return $exception->generateHttpResponse($response);
        
    } catch (\Exception $exception) {
        
        // Unknown exception
        $body = new Stream('php://temp', 'r+');
        $body->write($exception->getMessage());
        return $response->withStatus(500)->withBody($body);
        
    }
});
~~~
