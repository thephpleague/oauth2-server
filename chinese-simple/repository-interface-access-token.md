---
layout: default
title: AccessTokenRepositoryInterface文档
permalink: /access-token-repository-interface/
---

# 访问令牌存储库接口

## getNewToken() : AccessTokenEntityInterface

此方法应该返回 `\League\OAuth2\Server\Entities\AccessTokenEntityInterface`接口的实现. 您可以使用以下`traits `来帮助您从该接口实现所需的方法：

* `League\OAuth2\Server\Entities\Traits\AccessTokenTrait`
* `League\OAuth2\Server\Entities\Traits\EntityTrait`
* `League\OAuth2\Server\Entities\Traits\TokenEntityTrait`

## persistNewAccessToken() : void

创建新的访问令牌时，将调用此方法。您无需在此处做任何事情，但可能需要进行审核。

传入的访问令牌实体具有许多可以调用的方法，这些方法包含值得保存到数据库的数据：

* `getIdentifier() : string` 这是随机生成的访问令牌的唯一标识符（长度超过80个字符）
* `getExpiryDateTime() :  \DateTime` 访问令牌的到期日期和时间。
* `getUserIdentifier() : string|null` 访问令牌表示的用户标识符。
* `getScopes() : ScopeEntityInterface[]` 范围实体数组
* `getClient()->getIdentifier() : string` 求访问令牌的客户端的标识符。

JWT访问令牌包含到期日期，因此在使用时将被自动拒绝。您可以安全地从数据库中清除过期的访问令牌。

## revokeAccessToken() : void

当使用刷新令牌重新发出访问令牌时，将调用此方法。原始访问令牌被吊销，新的访问令牌被发布.

## isAccessTokenRevoked() : boolean

当资源服务器中间件验证访问令牌时，将调用此方法。如果访问令牌在过期之前已被手动吊销，则返回` true`。如果令牌仍然有效，则返回`false`。
