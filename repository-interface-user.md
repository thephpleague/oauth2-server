---
layout: default
title: UserRepositoryInterface documentation
permalink: /user-repository-interface/
---

# User Repository Interface

## getUserEntityByUserCredentials() : UserEntityInterface

This method is called to validate a user's credentials.

You can use the grant type to determine if the user is permitted to use the grant type.

You can use the client entity to determine to if the user is permitted to use the client.

If the client's credentials are validated you should return an instance of `\League\OAuth2\Server\Entities\Interfaces\UserEntityInterface`