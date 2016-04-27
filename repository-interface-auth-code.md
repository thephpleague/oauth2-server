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

When a new access token is created this method will be called. You don't have to do anything here but for auditing you probably want to.

The access token entity passed in has a number of methods you can call which contain data worth saving to a database:

* `getIdentifier() : string` this is randomly generated unique identifier (of 80+ characters in length) for the access token.
* `getExpiryDateTime() :  \DateTime` the expiry date and time of the access token.
* `getUserIdentifier() : string|null` the user identifier represented by the access token. 
* `getScopes() : ScopeEntityInterface[]` an array of scope entities
* `getClient()->getIdentifier() : string` the identifier of the client who requested the access token.

JWT access tokens contain an expiry date and so will be rejected automatically when used. You can safely clean up expired access tokens from your database.

## revokeAuthCode() : void

This method is called when an authorization code is exchanged for an access token.

## isAuthCodeRevoked() : boolean

This method is called before an authorization code is exchanged for an access token by the authorization server. Return `true` if the auth code has been manually revoked before it expired. If the auth code is still valid return `false`.