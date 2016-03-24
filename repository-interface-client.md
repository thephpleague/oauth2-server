---
layout: default
title: ClientRepositoryInterface documentation
permalink: /client-repository-interface/
---

# Client Repository Interface

## getClientEntity() : ClientEntityInterface

This method is called to validate a client's credentials.

The client secret may or may not be provided depending on the request sent by the client. If the client secret is sent it must be validated.

If the grant type is equal to `client_credentials` you should always validate the client secret.

You can use the grant type to determine if the client is permitted to use the grant type.

If the client's credentials are validated you should return an instance of `\League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface`