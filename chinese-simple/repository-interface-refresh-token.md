---
layout: default
title: RefreshTokenRepositoryInterface 文档
permalink: /refresh-token-repository-interface/
---

# Refresh Token Repository Interface

## getNewRefreshToken() : RefreshTokenEntityInterface

此方法应该返回   `\League\OAuth2\Server\Entities\RefreshTokenEntityInterface`接口的实现对象. 您可以使用以下`traits `来帮助您从该接口实现所需的方法：

* `League\OAuth2\Server\Entities\Traits\RefreshTokenTrait`
* `League\OAuth2\Server\Entities\Traits\EntityTrait`

## persistNewRefreshToken() : void

创建新的刷新令牌时，将调用此方法。您无需在此处执行任何操作，但可能需要进行审核。

传入的刷新令牌实体具有许多可以调用的方法，这些方法包含值得保存到数据库的数据：

* `getIdentifier() : string` 这是刷新令牌随机生成的唯一标识符（长度超过80个字符）
* `getExpiryDateTime() :  \DateTimeImmutable` 刷新令牌的到期日期和时间
* `getAccessToken()->getIdentifier() : string` 链接访问令牌的标识符。

JWT访问令牌包含到期日期，因此在使用时将被自动拒绝。您可以安全地从数据库中清除过期的访问令牌。

## revokeRefreshToken() : void

当使用刷新令牌重新发出访问令牌时，将调用此方法。原始的刷新令牌被吊销，而新的刷新令牌被发布。

## isRefreshTokenRevoked() : boolean

当使用刷新令牌发布新的访问令牌时，将调用此方法。如果刷新令牌在过期之前已被手动吊销，则返回`true`。如果令牌仍然有效，则返回`false`。
