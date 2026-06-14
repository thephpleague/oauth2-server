---
layout: default
title: ClientEntityInterface documentation
permalink: /entity-interface-client/
---

# Client Entity Interface

## getIdentifier() : string

This method should return a non-empty string representing the client's unique identifier.

## getName() : string

Return the client's name.

## getRedirectUri(): string|string[]

If a client has just one redirect URI associated with it, this method will return that redirect URI as as string. If the client has multiple redirect URIs registered, an array will be returned containing all of the registered redirect URIs.

## isConfidential(): bool

This method can be used to check if the client is confidential or not. Confidential clients are able to securely authenticate with authorization servers. If a client is not confidential, it is called a public client and is unable to use registered secrets, as it cannot keep them secure. Applications running in the browser or on a mobile device are unable to keep client secrets secure.

## FUTURE VERSION - supportsGrantType(string $grantType): bool

This signature is not currently included in the oauth2 client entity interface but we are listing it here as you can implement this on your clients now, if you wish. The function allows you to check if the calling client is allowed to use a particular grant type. If the client is not allowed to support the grant type, it will receive an `unauthorized_client` error response.

This is useful if you want to restrict clients to certain grant types which you might grant to others. This signature will be added to the next major version of the oauth2 library but its underlying functionality is already implemented should you wish to use it.
