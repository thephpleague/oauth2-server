---
layout: default
title: AuthCodeRepositoryInterface documentation
permalink: /auth-code-repository-interface/
---

# Auth Code Repository Interface

## getNewAuthCode() : AuthCodeEntityInterface

This method should return an implementation of `\League\OAuth2\Server\Entities\AuthCodeEntityInterface`. You can use the following traits to help you implement the required methods from that interface:

* `League\OAuth2\Server\Entities\Traits\EntityTrait`
* `League\OAuth2\Server\Entities\Traits\TokenEntityTrait`
* `League\OAuth2\Server\Entities\Traits\AuthCodeTrait`

## persistNewAuthCode() : void

When a new auth code is created this method will be called. You don't have to do anything here but for auditing you probably want to.

The auth code entity passed in has a number of methods you can call which contain data worth saving to a database:

* `getIdentifier() : string` this is randomly generated unique identifier (of 80+ characters in length) for the auth code.
* `getExpiryDateTime() :  \DateTimeImmutable` the expiry date and time of the auth code.
* `getUserIdentifier() : string|null` the user identifier represented by the auth code. 
* `getScopes() : ScopeEntityInterface[]` an array of scope entities
* `getClient()->getIdentifier() : string` the identifier of the client who requested the auth code.

The auth codes contain an expiry date and so will be rejected automatically if used when expired. You can safely clean up expired auth codes from your database.

## revokeAuthCode() : void

This method is called when an authorization code is exchanged for an access token. You can also use it in your own business logic.

## isAuthCodeRevoked() : boolean

This method is called before an authorization code is exchanged for an access token by the authorization server. Return `true` if the auth code is invalid and `false` if the auth code is still valid.
