---
layout: default
title: 升级指南
permalink: /upgrade-guide/
---

# 升级指南

## 7.x.x &rarr; 8.x.x

版本`8.x.x`需要PHP 7.1.0或更高版本。这是一个主要版本，因此包含一些与版本有关的重大更改
`7.x.x`。升级系统时，请仔细阅读以下注意事项。

### 公钥代码交换（PKCE）
`enableCodeExchangeProof`标志已从`AuthCodeGrant`中删除。此标志用于确定PKCE是否
应该在服务器上启用检查。服务器现在将在客户端发送_code challenge_时启动PKCE检查。

_`AuthCodeGrant_`具有一个新标记， `requireCodeChallengeForPublicClients`.该标志默认为`true`，并要求所有
公共客户端在请求访问令牌时提供PKCE _code challenge_

如果要禁用此功能，可以调用函数`disableRequireCodeChallengeForPublicClients()`将标志设置为`false`。为了安全，我们
建议您将此标志设置为`true`。

#### 客户端实体接口
为了将客户端标识为公共客户端还是机密客户端，服务器的版本8调用了新的`isConfidential()`函数。你
将需要更新您的客户实体实施，以包括此新功能。

### 密码授予的无效用户
如果在使用_Password Grant_时无法验证用户，则服务器将返回`invalid_grant`错误。
以前，服务器返回了`invalid_credentials`错误。您应该通知或更新任何可能期望的客户
 在这种情况下会收到`invalid_credentials`错误。

### 加密
现在，如果在运行这些函数时未设置任何加密密钥，则`encrypt()`和`decrypt()`函数会引发异常。

### 访问令牌
访问令牌不再具有功能`convertToJwt()`。它已被魔术方法`__toString()`取代。

### DateTimeImmutable
大多数`DateTime`实例已被`DateTimeImmutable`实例替换。您应该更改代码以使用
库进行了这些更改的`DateTimeImmutable`。受影响的接口及其功能如下

#### RefreshTokenEntityInterface
- `getExpiryDateTime()`
- `setExpiryDateTime()`

#### TokenInterface
- `getExpiryDateTime()`
- `setExpiryDateTime()`

请注意，实现这些接口的所有特征也已更新。

### JWT Headers

我们不再在已发布的JWT的标头中设置JTI声明。现在，JTI声明仅存在于
智威汤逊如果您的任何代码从标头中检索了JTI，则必须对其进行更新以从有效负载中检索此声明。

## 6.x.x &rarr; 7.x.x

版本`7.x.x`需要PHP 7.0.0或更高版本。该版本与该库的版本6.x.x不向后兼容。

clientRepositoryInterface中的`getClientEntity()`接口已更改。 `$grantType`参数现在必须默认为`null`。

```patch
  public function getClientEntity(
      $clientIdentifier,
-     $grantType,
+     $grantType = null,
      $clientSecret = null,
      $mustValidateSecret = true
  );
```
有关所有更改的完整列表，请参见[changelog](https://github.com/thephpleague/oauth2-server/blob/master/CHANGELOG.md).

## 5.1.x &rarr; 6.x.x

版本`6.x.x`与版本` 5.1.x`不向后兼容，仅要求您更改一行代码：

```patch
  $server = new AuthorizationServer(
      $clientRepository,
      $accessTokenRepository,
      $scopeRepository,
      $privateKeyPath,
+     'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen'
-      $publicKeyPath
  );
```

您需要做的就是用32位加密密钥替换传递到`AuthorizationServer`构造函数中的公共密钥。

要为` AuthorizationServer`生成加密密钥，请在终端中运行以下命令：

~~~ shell
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
~~~