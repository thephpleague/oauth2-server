---
layout: default
title: ClientRepositoryInterface 文档
permalink: /client-repository-interface/
---

# Client Repository Interface

## getClientEntity() : ClientEntityInterface

此方法应该返回 `\League\OAuth2\Server\Entities\ClientEntityInterface`接口的实现对象. 您可以使用以下`traits `来帮助您从该接口实现所需的方法：

* `\League\OAuth2\Server\Entities\Traits\ClientTrait`
* `\League\OAuth2\Server\Entities\Traits\EntityTrait`

## validateClient() : bool

调用此方法以验证客户的凭据。

根据客户端发送的请求，可以提供或可以不提供客户端机密。 如果客户端是机密的（即能够安全存储机密信息），则必须验证机密信息。

您可以使用授权类型来确定是否允许客户端使用授权类型。

如果客户的凭据已通过验证，则应返回“ true”，否则返回“ false”。