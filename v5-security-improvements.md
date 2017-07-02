---
layout: default
title: Authorization code grant
permalink: /v5-security-improvements/
---

# V5 Security Improvements

As part of Mozilla's [Secure Open Source](https://wiki.mozilla.org/MOSS/Secure_Open_Source) programme this library underwent a security audit.

The findings of this library have been fixed in the following releases - `5.1.4` and `6.0.0`

### 5.1.4

Version `5.1.4` is a backwards compatbile with other `5.1.x` releases.

You will notice in your server logs a message like this:

> You must set the encryption key going forward to improve the security of this library - see this page for more information https://oauth2.thephpleague.com/v5-security-improvements/

To supress this notice once you have instantiated an instance of `\League\OAuth2\Server\AuthorizationServer` you should call the `setEncryptionKey()` method passing in at least 32 bytes of random data.

You can generate this using `base64_encode(random_bytes(32))`. Alternatively if you're using a framework such as Laravel which has a encryption key already generated you can pass in that (in the case of Laravel use `env('APP_KEY')`).

For example:

```php
// Setup the authorization server
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

Version `6.0.0` is not backwards compatible with version `5.1.x` but only requires you to make one like of code change:

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

All you need to do is replace the public key that was being passed into the constructor of `AuthorizationServer` with a 32 bit encryption key.
