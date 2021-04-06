---
layout: default
title: 要求
permalink: /requirements/
---

# 要求

为了防止中间人攻击，授权服务器必须要求对[RFC2818](https://tools.ietf.org/html/rfc2818)定义的服务器身份验证使用TLS。到授权和令牌端点。客户端必须按照[RFC6125](https://tools.ietf.org/html/rfc6125)的定义并根据其对服务器身份验证的要求，验证授权服务器的TLS证书。

该库使用密钥密码术来加密和解密，以及验证签名的完整性。有关如何生成密钥的详细信息，请参见[安装](/installation)页面。

支持以下版本的PHP：

* PHP 7.2
* PHP 7.3
* PHP 7.4

需要安装扩展`openssl` 和`json` 

传递到服务器的所有HTTP消息均应为[符合PSR-7规范](https://www.php-fig.org/psr/psr-7/)。这样可以确保其他程序包和框架之间的互操作性。