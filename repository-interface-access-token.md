---
layout: default
title: AccessTokenRepositoryInterface documentation
permalink: /access-token-repository-interface/
---

# Access Token Repository Interface

## persistNewAccessToken() : void

When a new access token is created this method will be called. You don't have to do anything here but for auditing you probably want to.

The access token entity passed in has a number of methods you can call which contain data worth saving to a database:

* `getIdentifier() : string` this is randomly generated unique identifier (of 80+ characters in length) for the access token.
* `getExpiryDateTime() :  \DateTime` the expiry date and time of the access token.
* `getUserIdentifier() : string|null` the user identifier represented by the access token. 
* `getScopes() : ScopeEntityInterface[]` an array of scope entities
* `getClient()->getIdentifier() : string` the identifier of the client who requested the access token.

JWT access tokens contain an expiry date and so will be rejected automatically when used. You can safely clean up expired access tokens from your database.

## revokeAccessToken() : void

This method is called when a refresh token is used to reissue an access token. The original access token is revoked a new access token is issued.

## isAccessTokenRevoked() : boolean

This method is called when an access token is validated by the resource server middleware. Return `true` if the access token has been manually revoked before it expired. If the token is still valid return `false`.