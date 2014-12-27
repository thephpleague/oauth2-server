---
layout: default
title: Token types
permalink: /token-types/
---

# Token Types

This library supports Bearer and MAC tokens out of the box.

## Bearer Tokens

Bearer tokens are the default type of access tokens. They are automatically enabled when either an Authorization Server or Resource Server are initialized.

If you [implement the core storage interfaces](/implementing-storage-interfaces/) then you don't need to do anymore.

When calling an API endpoint bearer tokens are either presented either in the query string (e.g. `?access_token=abcdef`) or as an authorization header (e.g. `Authorization: Bearer abcdef`).

## MAC Tokens

A MAC (Message Authentication Code) is a short piece of information used to authenticate a message and to provide integrity and authenticity assurances on the message. Integrity assurances detect accidental and intentional message changes, while authenticity assurances affirm the message's origin.

When MAC tokens are enabled a _MAC key_ is presented with the access token. When a client makes an API request it computes a MAC signature that sent with the access token to provide cryptographic verification of the request. Because only the client who was presented with the access token has the mac key it can prevent sniffed access tokens from being used by unauthorized clients.

To enable support for MAC tokens you should implement the `League\OAuth2\Server\Storage\MacTokenInterface` storage interface so that the authorization server can save generated MAC keys and the resource server can find them.

Then set the MAC Storage object and set the token type to be MAC tokens.

~~~ php
$server->setMacStorage($macStorage);
$server->setTokenType(new League\OAuth2\Server\TokenType\MAC);
~~~

You're good to go!

When calling API endpoints that are secured by MAC tokens the client should send an authorization header like so:

~~~
Authorization: MAC id="the access token", ts="current unix timestamp", nonce="random string", mac="base64 encoded signature"
~~~

To calculate the signature concatenate the following parameters with newline characters:

1. The timestamp (as specified in the `ts` attribute in the authorization header)
2. The nonce (as specified in the `nonce` attribute in the authorization header)
3. The HTTP request method in uppercase
4. The full HTTP request URI (as specified in [RFC2616] section 5.1.2)
5. The hostname
6. The port

Assuming the request was:

~~~ http
POST /users HTTP/1.1
Host: api.example.com
~~~

The concatenated string would be:

~~~
1419723092
9s0df90s09d
POST
https://api.example.com/users
api.example.com
443
~~~

Then sign this string with the MAC key (use sha-256 algorithm) and base64 encode it - `hash_hmac` is the function to this in PHP.