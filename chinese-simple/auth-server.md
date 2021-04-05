---
layout: default
title: 授权服务器
permalink: /authorization-server/index
---

# 授权服务器

授权服务器授权并接受来自客户端的授权请求。它负责发布访问和刷新令牌。

## enableGrantType() :null|DateInterval

默认情况下，实例化的AuthorizationServer将不接受任何授予类型。要添加授权类型，请调用` enableGrantType`方法，并向其传递一个` GrantTypeInterface`用于授权，并启用一个可选的DateInterval，指定该授权类型发出的任何访问令牌的默认生存时间。

## validateAuthorizationRequest() : AuthorizationRequest

此功能用于验证传入的授权请求，检查用户是否已授权客户端访问其受保护的资源。如果检查通过，则服务器将发出`AuthorizationRequest`的实例，该实例可与` completeAuthorizationRequest()`方法一起使用。
此授权码和隐式授予使用此方法。

## completeAuthorizationRequest() : ResponseInterface

未完待续...

## respondToAccessTokenRequest() : ResponseInterface

此方法用于响应对访问令牌的请求。它将验证客户端和作为请求的一部分收到的授权代码，如果成功，则向客户端发出访问令牌。

## getResponseType() : ResponseTypeInterface

用于获取授权将返回的响应类型。响应类型必须是`ResponseTypeInterface`的实现。如果不是，则发出默认的` BearerTokenResponse`。

## setDefaultScope() : null

首次实例化授权服务器时，没有设置默认范围。如果服务器收到未指定任何范围的授权请求，它将通过发出无效的范围响应来拒绝该请求。如果使用此方法设置了默认范围，则将为没有范围的授权请求分配服务器的默认范围集。
