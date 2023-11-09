---
layout: default
title: Which OAuth 2.0 grant should I use?
permalink: /authorization-server/which-grant/
---

# Which OAuth 2.0 grant should I implement?

A grant is a method of acquiring an access token. Deciding which grants to implement depends on the type of client the end user will be using, and the experience you want for your users.

<figure>
    <img src="/images/grants.min.svg" style="width:100%">
</figure>


## Terminology

Some of the terminology used in the OAuth 2 framework is detailed here, to help you choose the correct grant for your use-case.

### First party or third party client?

A first party client is a client that you trust enough to handle the end user's authorization credentials. For example Spotify's iPhone app is owned and developed by Spotify so therefore they implicitly trust it.

A third party client is a client that you don't trust.

### Access Token Owner?

An access token represents a permission granted to a client to access some protected resources.

If you are authorizing a machine to access resources and you don't require the permission of a user to access said resources you should implement the [client credentials grant](/authorization-server/client-credentials-grant/).

If you require the permission of a user to access resources you need to determine the client type.

### Client Type?

Depending on whether or not the client is capable of keeping a secret you can determine which grant the client should use.

If the client is a web application that has a server side component then you should implement the [authorization code grant](/authorization-server/auth-code-grant/).

If the client is a web application that has runs entirely on the front end (e.g. a single page web application) or a native application such as a mobile app you should implement the [authorization code grant](/authorization-server/auth-code-grant/) with the PKCE extension.

Third party native applications should use the [authorization code grant](/authorization-server/auth-code-grant/) (via the native browser, not an embedded browser - e.g. for iOS push the user to Safari or use [SFSafariViewController](https://developer.apple.com/library/ios/documentation/SafariServices/Reference/SFSafariViewController_Ref/), <u>don't</u> use an embedded [WKWebView](https://developer.apple.com/library/ios/documentation/WebKit/Reference/WKWebView_Ref/)).

## Legacy Grants

The _Password Grant_ and _Implicit Grant_ are not included in our recommendation diagram as these grants have several drawbacks and/or are no longer considered to be best practice.

### Password Grant

We *strongly* recommend that you use the Authorization Code flow over the Password grant for several reasons.

The Authorization Code Grant redirects to the authorization server. This provides the authorization server with the opportunity to prompt the user for multi-factor authentication options, take advantage of single-sign-on sessions, or use third-party identity providers.

The Password grant does not provide any built-in mechanism for these and must be extended with custom code.

### Implicit Grant

It is recommended that clients no longer use the Implict Grant. This grant cannot be protected by PKCE which is recommended for native apps.

In addition, access tokens grants via the implicit flow cannot be refreshed without user interaction, making the authorization code grant flow, which can issue refresh tokens, the more practical option for native app authorizations that require refreshing of access tokens.

You should use the Authorization Code flow with no secret for native and browser-based apps.
