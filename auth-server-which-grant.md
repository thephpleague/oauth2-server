---
layout: default
title: Which OAuth 2.0 grant should I use?
permalink: /authorization-server/which-grant/
---

# Which OAuth 2.0 grant should I implement?

A grant is a method of acquiring an access token. Deciding which grants to implement depends on the type of client the end user will be using, and the experience you want for your users.

<figure>
    <img src="/images/grants.svg" style="width:100%">
</figure>

## First party or third party client?

A first party client is a client that you trust enough to handle the end user's authorization credentials. For example Spotify's iPhone app is owned and developed by Spotify so therefore they implicitly trust it.

A third party client is a client that you don't trust.

## Access Token Owner?

An access token represents a permission granted to a client to access some protected resources.

If you are authorizing a machine to access resources and you don't require the permission of a user to access said resources you should implement the [client credentials grant](/authorization-server/client-credentials-grant/).

If you require the permission of a user to access resources you need to determine the client type.

## Client Type?

Depending on whether or not the client is capable of keeping a secret will depend on which grant the client should use.

If the client is a web application that has a server side component then you should implement the [authorization code grant](/authorization-server/auth-code-grant/).

If the client is a web application that has runs entirely on the front end (e.g. a single page web application) you should implement the [password grant](/authorization-server/resource-owner-password-credentials-grant/) for a first party clients and the [implicit grant](/authorization-server/implicit-grant/) for a third party clients.

If the client is a native application such as a mobile app you should implement the [password grant](/authorization-server/resource-owner-password-credentials-grant/).

Third party native applications should use the [authorization code grant](/authorization-server/auth-code-grant/) (via the native browser, not an embedded browser - e.g. for iOS push the user to Safari or use [SFSafariViewController](https://developer.apple.com/library/ios/documentation/SafariServices/Reference/SFSafariViewController_Ref/), <u>don't</u> use an embedded [WKWebView](https://developer.apple.com/library/ios/documentation/WebKit/Reference/WKWebView_Ref/)).
