---
layout: default
title: V5安全性改进
permalink: /v5-security-improvements/
---

# V5安全性改进

作为Mozilla的[安全开源](https://wiki.mozilla.org/MOSS/Secure_Open_Source)程序的一部分，该库经过了安全审核。

该库的发现问题已在以下版本-`5.1.4`和`6.0.0`中修复。

### 5.1.4

版本`5.1.4`向后兼容其他版本`5.1.x`。

您会在服务器日志中注意到这样的消息：

> 您必须继续设置加密密钥以提高该库的安全性-有关更多信息，请参见此页面 https://oauth2.thephpleague.com/v5-security-improvements/

一旦实例化了`\League\OAuth2\Server\AuthorizationServer`的实例，就应该调用`setEncryptionKey()`方法传入至少32个字节的随机数据，以消除此通知。

您可以使用`base64_encode(random_bytes(32))`生成它。或者，如果您使用的是一个框架，比如Laravel，它已经生成了一个加密密钥，那么您可以传入这个框架（在Laravel的情况下，使用`env('APP_KEY')`）。

For example:

```php
// 设置授权服务器
$server = new AuthorizationServer(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKeyPath,
    $publicKeyPath
);
$server->setEncryptionKey('lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen');
```

### 6.0.0

版本`6.0.0`与版本`5.1.x`不向后兼容，但只需要更改一行代码：

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

您只需将传递到`AuthorizationServer`的构造函数中的公钥替换为32字节的加密密钥。

要为`AuthorizationServer`生成加密密钥，请在终端中运行以下命令：

~~~ shell
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
~~~
