---
layout: default
title: ClientRepositoryInterface documentation
permalink: /client-repository-interface/
---

# Client Repository Interface

## getClientEntity() : ClientEntityInterface

This method is called to validate a client's credentials.

The client secret may or may not be provided depending on the request sent by the client. The boolean `$mustValidateSecret` parameter will indicate whether or not the client secret must be validated. If the client is confidential (i.e. is capable of securely storing a secret) and `$mustValidateSecret === true` then the secret must be validated.

You can use the grant type to determine if the client is permitted to use the grant type.

If the client's credentials are validated you should return an instance of `\League\OAuth2\Server\Entities\Interfaces\ClientEntityInterface`

There are two grants you can use to help you implement some of the `ClientEntityInterface` methods:

* `\League\OAuth2\Server\Entities\Traits\ClientTrait`
* `\League\OAuth2\Server\Entities\Traits\EntityTrait`