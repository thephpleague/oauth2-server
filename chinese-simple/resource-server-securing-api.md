---
layout: default
title: 保护您的API
permalink: /resource-server/securing-your-api/
---

# 保护您的API

该库提供了PSR-7友好的资源服务器中间件，可以验证访问令牌。

## 设置

无论您在何处初始化对象，都可以使用存储接口初始化资源服务器的新实例：

~~~ php
// 初始化我们的仓库
$accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface

// 授权服务器公钥的路径
$publicKeyPath = 'file://path/to/public.key';
        
// 设置授权服务器
$server = new \League\OAuth2\Server\ResourceServer(
    $accessTokenRepository,
    $publicKeyPath
);
~~~

添加中间件到您的逻辑中

~~~ php
new \League\OAuth2\Server\Middleware\ResourceServerMiddleware($server);
~~~

## 使用

传入请求上的授权标头将被自动验证。

如果访问令牌有效，则将在ServerRequest上设置以下属性：

* `oauth_access_token_id` - 访问令牌标识符
* `oauth_client_id` - 客户端标识符
* `oauth_user_id` -访问令牌代表的用户标识符
* `oauth_scopes` - 字符串作用域标识符数组

如果授权无效，则将抛出`OAuthServerException::accessDenied`实例。
