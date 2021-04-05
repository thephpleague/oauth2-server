---
layout: default
title: 我应该使用哪个OAuth 2.0授权？
permalink: /authorization-server/which-grant/
---

# 我应该使用哪一种OAuth 2.0授权？

授权是一种获取访问令牌的方法。确定要实施的授权方法取决于最终用户将使用的客户端类型，以及您希望为用户提供的体验。

<figure>
    <img src="/images/grants.min.svg" style="width:100%">
</figure>


## 术语

此处详细介绍了OAuth 2框架中使用的一些术语，以帮助您为用例选择正确的授权。

### 第一方还是第三方客户？

第一方客户端是您足够信任的客户端，可以处理最终用户的授权凭据。例如，Spotify的iPhone应用程序由Spotify拥有和开发，因此他们暗中信任它。

第三方客户是您不信任的客户。

### 访问令牌所有者？

访问令牌表示授予客户端访问某些受保护资源的权限。
如果您要授权计算机访问资源，并且不需要用户许可就可以访问上述资源，则应实施[客户端凭据授予](/authorization-server/client-credentials-grant/).

如果需要用户的许可才能访问资源，则需要确定客户端类型。

### 客户类型？

取决于客户端是否能够保守秘密，将取决于客户端应使用哪种授权。

如果客户端是完全在前端运行的Web应用程序（例如单页Web应用程序）或本机应用程序（例如移动应用程序），则应实施[授权码授予](/authorization-server/auth-code-grant/).

如果客户端是完全在前端运行的Web应用程序（例如单页Web应用程序）或本机应用程序（例如移动应用程序），则应实施[授权码授予](/authorization-server/auth-code-grant/) （带有PKCE扩展名）

第三方本机应用程序应使用[授权代码授予](/authorization-server/auth-code-grant/) (通过本机浏览器，而不是嵌入式浏览器-例如，对于iOS，将用户推送到Safari或使用[SFSafariViewController](https://developer.apple.com/library/ios/documentation/SafariServices/Reference/SFSafariViewController_Ref/), <u>请勿</u> 使用嵌入式 [WKWebView](https://developer.apple.com/library/ios/documentation/WebKit/Reference/WKWebView_Ref/)).

## 旧版授权

_Password Grant_和_Implicit Grant_未包含在我们的推荐图中，因为这些授权有很多缺点和/或不再被视为最佳实践。

### 密码授予

我们**强烈**建议您出于多种原因在密码授权上使用授权码流程。

授权代码授予将重定向到授权服务器。这为授权服务器提供了提示用户输入多因素身份验证选项，利用单点登录会话或使用第三方身份提供者的机会。

密码授予不提供任何内置机制，必须使用自定义代码进行扩展。

### 隐式授予

建议客户不再使用“隐式授予”。推荐给本机应用程序的PKCE不能保护此授权。

此外，在没有用户交互的情况下，无法刷新通过隐式流的访问令牌授予，这使得授权代码授予流（可以发出刷新令牌）成为需要刷新访问令牌的本机应用程序授权的更为实用的选择。

对于本机和基于浏览器的应用程序，您不应使用授权码流。