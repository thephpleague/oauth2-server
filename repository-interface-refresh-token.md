---
layout: default
title: RefreshTokenRepositoryInterface documentation
permalink: /refresh-token-repository-interface/
---

# Refresh Token Repository Interface

## getNewRefreshToken() : RefreshTokenEntityInterface

This method should return an implementation of `\League\OAuth2\Server\Entities\RefreshTokenEntityInterface`. You can use the following traits to help you implement the required methods from that interface:

* `League\OAuth2\Server\Entities\Traits\RefreshTokenTrait`
* `League\OAuth2\Server\Entities\Traits\EntityTrait`

## persistNewRefreshToken() : void

When a new refresh token is created this method will be called. You don't have to do anything here but for auditing you might want to.

The refresh token entity passed in has a number of methods you can call which contain data worth saving to a database:

* `getIdentifier() : string` this is randomly generated unique identifier (of 80+ characters in length) for the refresh token.
* `getExpiryDateTime() :  \DateTimeImmutable` the expiry date and time of the refresh token.
* `getAccessToken()->getIdentifier() : string` the linked access token's identifier.

JWT access tokens contain an expiry date and so will be rejected automatically when used. You can safely clean up expired access tokens from your database.

## revokeRefreshToken() : void

This method is called when a refresh token is used to reissue an access token. The original refresh token is revoked a new refresh token is issued.

## isRefreshTokenRevoked() : boolean

This method is called when an refresh token is used to issue a new access token. Return `true` if the refresh token has been manually revoked before it expired. If the token is still valid return `false`.
