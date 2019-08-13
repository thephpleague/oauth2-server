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

## Access Token Owner?

An access token represents a permission granted to a client to access some protected resources.

If you are authorizing a machine to access resources and you don't require the permission of a user to access said resources you should implement the [client credentials grant](/authorization-server/client-credentials-grant/).

If you require the permission of a user to access resources you need to determine the client type.

## Client Type?

Depending on whether or not the client is capable of keeping a secret will depend on which grant the client should use.

If the client is a web application that has a server side component then you should implement the [authorization code grant](/authorization-server/auth-code-grant/).

If the client is a web application that has runs entirely on the front end (e.g. a single page web application) or a native application such as a mobile app you should implement the [authorization code grant](/authorization-server/auth-code-grant/) with the PKCE extension.

Third party native applications should use the [authorization code grant](/authorization-server/auth-code-grant/) (via the native browser, not an embedded browser - e.g. for iOS push the user to Safari or use [SFSafariViewController](https://developer.apple.com/library/ios/documentation/SafariServices/Reference/SFSafariViewController_Ref/), <u>don't</u> use an embedded [WKWebView](https://developer.apple.com/library/ios/documentation/WebKit/Reference/WKWebView_Ref/)).
