---
layout: default
title: 快速开始
permalink: /installation/
---

# 安装

推荐的安装方法是使用 [Composer](https://getcomposer.org).

在您的项目根目录中运行:

~~~ shell
composer require league/oauth2-server
~~~

确保您已将项目设置为 [autoload Composer-installed packages](https://getcomposer.org/doc/01-basic-usage.md#autoloading)自加载Composer.

根据您要实现的[哪一个授权](/authorization-server/which-grant/) 您将需要实现许多对应的一系列接口。每个授权文档页面都列出了所需的授权方式，每个授权方式界面都有其自己的文档页面

预期存储库将返回（成功）[实体接口] (https://github.com/thephpleague/oauth2-server/tree/master/src/Entities); 为了使与现有实体和模型的集成尽可能容易, 已将所有必需的方法实现为traits以便于你的使用。

## 生成公钥和私钥

公钥/私钥对用于签名和验证传输的JWT。 _Authorization Server_拥有用于签名令牌的私钥，而_Resource Server_拥有用于验证签名的相应公钥。要生成私钥，请在终端上运行以下命令：

~~~ shell
openssl genrsa -out private.key 2048
~~~

如果要为私钥提供密码短语，请运行以下命令：

~~~ shell
openssl genrsa -aes128 -passout pass:_passphrase_ -out private.key 2048
~~~

然后从私钥中提取公钥：

~~~ shell
openssl rsa -in private.key -pubout -out public.key
~~~

或使用私钥生成中提供的密码：

~~~ shell
openssl rsa -in private.key -passin pass:_passphrase_ -pubout -out public.key
~~~

私钥必须保密（即不在授权服务器的Web根目录中）。授权服务器还需要公用密钥。

如果密码已用于生成私钥，则必须将其提供给授权服务器。

公钥应分发给验证访问令牌的任何服务（例如资源服务器）。

## 生成加密密钥

加密密钥用于加密授权和刷新代码. The `AuthorizationServer` 接受两种加密密钥,  `string` 类型的密码 或者 [Secure PHP Encryption Library](https://github.com/defuse/php-encryption) 的 `\Defuse\Crypto\Key` 对象 .

### 字符串密码

`string` 密码的强度可以根据所选择的密码而有所不同. 为了将其转换为强加密密钥，使用了[PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) 密钥派生功能。
此功能从密码派生加密密钥，并且在设计上很慢。它使用大量的CPU资源，只需不到一秒钟的时间，因此可以对密码进行密钥扩展，以减少遭受暴力攻击的脆弱性。

以在终端中运行以下命令 为 `AuthorizationServer`生成 `string` 密码 

~~~ shell
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
~~~

### 密码对象

`\Defuse\Crypto\Key` 是一个很强的加密密钥。与使用`string`密码相比，这消除了使用慢速密钥派生功能的需要，从而减少了加密和解密时间.

A `Key` can be generated with the `generate-defuse-key` script. To generate a `Key` for the `AuthorizationServer` run the following command in the terminal:
可以使用 `generate-defuse-key` 脚本生成`Key`密码对象。以在终端中运行以下命令 为 `AuthorizationServer`生成 `Key` 密码 

~~~ shell
vendor/bin/generate-defuse-key
~~~

 `string` 可以作为 `Key`加载，使用 `Key::loadFromAsciiSafeString($string)`. 比如：

```php
  use \Defuse\Crypto\Key;
  $server = new AuthorizationServer(
      $clientRepository,
      $accessTokenRepository,
      $scopeRepository,
      $privateKeyPath,
      Key::loadFromAsciiSafeString($encryptionKey)
);
```
