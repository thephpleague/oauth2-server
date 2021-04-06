---
layout: default
title: AuthCodeRepositoryInterface文档
permalink: /auth-code-repository-interface/
---

# 身份验证代码存储库接口

## getNewAuthCode() : AuthCodeEntityInterface

此方法应该返回  `\League\OAuth2\Server\Entities\AuthCodeEntityInterface`接口的实现对象. 您可以使用以下`traits `来帮助您从该接口实现所需的方法：

* `League\OAuth2\Server\Entities\Traits\EntityTrait`
* `League\OAuth2\Server\Entities\Traits\TokenEntityTrait`
* `League\OAuth2\Server\Entities\Traits\AuthCodeTrait`

## persistNewAuthCode() : void

创建新的访问令牌时，将调用此方法。您无需在此处做任何事情，但可能需要进行审核。

传入的auth代码实体具有许多可以调用的方法，这些方法包含值得保存到数据库的数据：

* `getIdentifier() : string`  这是随机生成的访问令牌的唯一标识符（长度超过80个字符）
* `getExpiryDateTime() :  \DateTimeImmutable` 验证码的到期日期和时间。
* `getUserIdentifier() : string|null` 验证码表示的用户标识符。
* `getScopes() : ScopeEntityInterface[]` 范围实体数组
* `getClient()->getIdentifier() : string` 请求身份验证代码的客户端的标识符。

身份验证代码包含有效期，因此，如果在过期时使用，则会被自动拒绝。您可以安全地从数据库中清除过期的身份验证代码。

## revokeAuthCode() : void

当将授权代码交换为访问令牌时，将调用此方法。您也可以在自己的业务逻辑中使用它。

## isAuthCodeRevoked() : boolean

在授权服务器将授权代码交换访问令牌之前，将调用此方法。如果auth代码在过期之前已被手动吊销，则返回true。如果验证码仍然有效，则返回“ false”.
