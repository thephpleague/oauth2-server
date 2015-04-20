---
layout: default
title: Installation
permalink: /implementing-storage-interfaces/
---

# Implementing the storage interfaces

In order to use both the resource server and authorization server you need to implement a number of interfaces.

If you are using the resource server you need to implement the following interfaces:

* `League\OAuth2\Server\Storage\SessionInterface` - contains methods for retrieving and setting sessions
* `League\OAuth2\Server\Storage\AccessTokenInterface` - contains methods for retrieving, creating and deleting access tokens
* `League\OAuth2\Server\Storage\ClientStorage` - single method to get a client
* `League\OAuth2\Server\Storage\ScopeStorage` - single method to get a scope

If you are using the authorization server you need to implement the following interfaces:

* `League\OAuth2\Server\Storage\SessionInterface` - contains methods for retrieving and setting sessions
* `League\OAuth2\Server\Storage\AccessTokenInterface` - contains methods for retrieving, creating and deleting access tokens
* `League\OAuth2\Server\Storage\ClientStorage` - single method to get a client
* `League\OAuth2\Server\Storage\ScopeStorage` - single method to get a scope

If you are using the authorization code grant you also need to implement:

* `League\OAuth2\Server\Storage\AuthCodeInterface` - contains methods for retrieving, creating and deleting authorization codes

If you are using the refresh token grant you also need to implement:

* `League\OAuth2\Server\Storage\RefreshTokenInterface` - contains methods for retrieving, creating and deleting refresh tokens

Once you have written your class implementations then inject them into the server like so:

~~~ php
// Resource server
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

// Authorization server
$server->setSessionStorage(new Storage\SessionStorage);
$server->setAccessTokenStorage(new Storage\AccessTokenStorage);
$server->setRefreshTokenStorage(new Storage\RefreshTokenStorage);
$server->setClientStorage(new Storage\ClientStorage);
$server->setScopeStorage(new Storage\ScopeStorage);
$server->setAuthCodeStorage(new Storage\AuthCodeStorage);
~~~

If you are using a relational database you can find some example storage implementations in the `examples/relational` folder in the codebase.

You don't have to use a database to store all of your settings
