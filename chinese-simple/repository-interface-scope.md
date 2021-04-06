---
layout: default
title: ScopeRepositoryInterface 文档
permalink: /scope-repository-interface/
---

# 作用域存储库接口

## getScopeEntityByIdentifier() : ScopeEntityInterface

调用此方法以验证范围。

如果范围有效，则应返回 `\League\OAuth2\Server\Entities\Interfaces\ScopeEntityInterface`的实例

## finalizeScopes() : ScopeEntityInterface[]

在创建访问令牌或授权代码之前立即调用此方法。

在给定客户端的情况下，授予类型和可选的用户标识符将验证所请求的范围集是否有效，并可以选择附加其他范围或删除所请求的范围。

此方法对于与您自己的应用程序的权限系统集成很有用。

您必须返回一个ScopeEntityInterface实例数组； 原始范围或更新的范围。
