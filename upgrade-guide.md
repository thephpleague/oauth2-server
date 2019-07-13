---
layout: default
title: Upgrade Guide
permalink: /upgrade-guide/
---

# Upgrade Guide

## 7.x.x &rarr; 8.x.x

Version `8.x.x` requires PHP 7.1.0 or higher. This is a major release so contains some breaking changes from version
`7.x.x`. Please read the following notes carefully when upgrading your system.

### Public Key Code Exchange (PKCE)
The `enableCodeExchangeProof` flag has been removed from the AuthCodeGrant. This flag was used to determine whether PKCE
checks should be enabled on the server. The server will now initiate PKCE checks whenever a client sends a _code
challenge_.

The _AuthCodeGrant_ has a new flag, `requireCodeChallengeForPublicClients`. The flag defaults to true and requires all
public clients to provide a PKCE code challenge when requesting an access token. If you want to disable this, you can
call the function `disableRequireCodeChallengeForPublicClients()` which will set the flag to false. For security, we 
recommend you keep this flag set to true.

#### Client Entity Interface
To identify a client as public or confidential, version 8 of the server calls the new `isConfidential()` function. You
will need to update your client entity implementation to include this new function.

### Invalid User for Password Grant
If a user cannot be validated when using the _Password Grant_, the server will return an `invalid_grant` error.
Previously the server returned an `invalid_credentials` error. You should notify or update any clients that might expect
 to receive an `invalid_credentials` error in this scenario.

### Crypt Trait
The `encrypt()` and `decrypt()` functions now throw exceptions if no encryption key is set when running these functions.

### Access Tokens
Access tokens no longer have the function `convertToJwt()`. This has been replaced with the magic method `__toString()`.

### DateTimeImmutable
Most instances of `DateTime` have been replaced with `DateTimeImmutable` instances. You should change your code to use
`DateTimeImmutable` where the library has made these changes. The affected interfaces and their functions are as
follows:

#### RefreshTokenEntityInterface
- `getExpiryDateTime()`
- `setExpiryDateTime()`

#### TokenInterface
- `getExpiryDateTime()`
- `setExpiryDateTime()`

Please note that any traits that implement these interfaces have also been updated.

### JWT Headers

We no longer set the JTI claim in the header of an issued JWT. The JTI claim is now only present in the payload of the 
JWT. If any of your code retrieved the JTI from the header, you must update it to retrieve this claim from the payload.

## 6.x.x &rarr; 7.x.x

Version `7.x.x` requires PHP 7.0.0 or higher. This version is not backwards compatible with version `6.x.x` of the library.

The interface for `getClientEntity()` in the `clientRepositoryInterface` has changed. The `$grantType` argument must now default to `null`.

```patch
  public function getClientEntity(
      $clientIdentifier,
-     $grantType,
+     $grantType = null,
      $clientSecret = null,
      $mustValidateSecret = true
  );
```
Please see the [changelog](https://github.com/thephpleague/oauth2-server/blob/master/CHANGELOG.md) for a complete list of all changes.

## 5.1.x &rarr; 6.x.x

Version `6.x.x` is not backwards compatible with version `5.1.x` but only requires you to make one line of code change:

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

To generate an encryption key for the `AuthorizationServer` run the following command in the terminal:

~~~ shell
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
~~~ 