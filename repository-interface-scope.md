---
layout: default
title: ScopeRepositoryInterface documentation
permalink: /scope-repository-interface/
---

# Scope Repository Interface

## getScopeEntityByIdentifier() : ScopeEntityInterface

This method is called to validate a scope.

If the scope is valid you should return an instance of `\League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface`

## finalizeScopes() : ScopeEntityInterface[]

This method is called right before an access token or authorization code is created.

Given a client, grant type and optional user identifier validate the set of scopes requested are valid and optionally append additional scopes or remove requested scopes.

This method is useful for integrating with your own app's permissions system.

You must return an array of `ScopeEntityInterface` instances; either the original scopes or an updated set.
