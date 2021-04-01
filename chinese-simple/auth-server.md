---
layout: default
title: The Authorization Server
permalink: /authorization-server/index
---

# The Authorization Server

The Authorization server authorizes and accepts authorization requests from a client. It is responsible for issuing access and refresh tokens.

## enableGrantType() :null|DateInterval

By default, an instantiated AuthorizationServer will not accept any grant types. To add a grant type, call the `enableGrantType` method, passing it a `GrantTypeInterface` for the grant tht should be enabled and an optional DateInterval, specifying the default time to live for any access tokens issued by the grant type.

## validateAuthorizationRequest() : AuthorizationRequest

This function is used to validate an incoming authorization request, checking that a user has authorized a client to access their protected resources. If the check passes, the server will issue an instance of `AuthorizationRequest`, which can be used with the `completeAuthorizationRequest()` method. 

This Authorization Code and Implicit Grant make use of this method.

## completeAuthorizationRequest() : ResponseInterface

To complete...

## respondToAccessTokenRequest() : ResponseInterface

This method is used to respond to a request for an access token. It will validate the client and authorization code received as part of the request, and if successful, issue an access token to the client.

## getResponseType() : ResponseTypeInterface

Used to get the response type that grants will return. The response type must be an implementation of the `ResponseTypeInterface`. If it is not, a default `BearerTokenResponse` is issued.

## setDefaultScope() : null

When the Authorization Server is first instantiated, it has no default scope set. If the server receieves an authorization request that does not specify any scope, it will reject the request by issuing an invalid scope response. If a default scope is set using this method, authorization requests without a scope will be assigned the default scope set for the server.
