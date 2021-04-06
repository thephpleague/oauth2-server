---
layout: default
title: UserRepositoryInterface 文档
permalink: /user-repository-interface/
---

# 用户存储库接口

## getUserEntityByUserCredentials() : UserEntityInterface

调用此方法以验证用户的凭据。

您可以使用授权类型来确定是否允许用户使用授权类型。

您可以使用客户端实体来确定是否允许用户使用客户端。

如果客户端的凭据已通过验证，则应返回 `\League\OAuth2\Server\Entities\Interfaces\UserEntityInterface`的实例