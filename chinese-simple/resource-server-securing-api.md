---
layout: default
title: Securing your API
permalink: /resource-server/securing-your-api/
---

# Securing your API

This library provides a PSR-7 friendly resource server middleware that can validate access tokens.

## Setup

Wherever you intialize your objects, initialize a new instance of the resource server with the storage interfaces:

~~~ php
// Init our repositories
$accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface

// Path to authorization server's public key
$publicKeyPath = 'file://path/to/public.key';
        
// Setup the authorization server
$server = new \League\OAuth2\Server\ResourceServer(
    $accessTokenRepository,
    $publicKeyPath
);
~~~

Then add the middleware to your stack:

~~~ php
new \League\OAuth2\Server\Middleware\ResourceServerMiddleware($server);
~~~

## Implementation

The authorization header on an incoming request will automatically be validated.

If the access token is valid the following attributes will be set on the ServerRequest:

* `oauth_access_token_id` - the access token identifier
* `oauth_client_id` - the client identifier
* `oauth_user_id` - the user identifier represented by the access token
* `oauth_scopes` - an array of string scope identifiers

If the authorization is invalid an instance of `OAuthServerException::accessDenied` will be thrown.
