---
layout: default
title: ClientRepositoryInterface documentation
permalink: /client-repository-interface/
---

# Client Repository Interface

## getClientEntity() : ClientEntityInterface

This method should return an implementation of `\League\OAuth2\Server\Entities\ClientEntityInterface`. You can use the following traits to help you implement the required methods from that interface:

* `\League\OAuth2\Server\Entities\Traits\ClientTrait`
* `\League\OAuth2\Server\Entities\Traits\EntityTrait`

## validateClient() : bool

This method is called to validate a client's credentials.

The client secret may or may not be provided depending on the request sent by the client. If the client is confidential (i.e. is capable of securely storing a secret) then the secret must be validated.

You can use the grant type to determine if the client is permitted to use the grant type.

If the client's credentials are validated you should return `true`, otherwise return `false`.
