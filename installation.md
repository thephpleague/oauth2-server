---
layout: default
title: Installation
permalink: /installation/
---

# Installation

The recommended installation method is using [Composer](https://getcomposer.org).

In your project root just run:

~~~ shell
composer require league/oauth2-server
~~~

Ensure that you’ve set up your project to [autoload Composer-installed packages](https://getcomposer.org/doc/01-basic-usage.md#autoloading).

Depending on [which grant](/authorization-server/which-grant/) you are implementing you will need to implement a number of repository interfaces. Each grant documentation page lists which repositories are required, and each repository interface has it's own documentation page.

The repositories are expected to return (on success) instances of [entity interfaces](https://github.com/thephpleague/oauth2-server/tree/master/src/Entities); to make integration with your existing entities and models as easy as possible though, all required methods have been implemented as traits that you can use.

## Generating public and private keys

The public/private key pair is used to sign and verify JWTs transmitted. The _Authorization Server_ possesses the private key to sign tokens and the _Resource Server_ possesses the corresponding public key to verify the signatures. To generate the private key run this command on the terminal:

~~~ shell
openssl genrsa -out private.key 2048
~~~

If you want to provide a passphrase for your private key run this command instead:

~~~ shell
openssl genrsa -aes128 -passout pass:_passphrase_ -out private.key 2048
~~~

then extract the public key from the private key:

~~~ shell
openssl rsa -in private.key -pubout -out public.key
~~~

or use your passphrase if provided on private key generation:

~~~ shell
openssl rsa -in private.key -passin pass:_passphrase_ -pubout -out public.key
~~~

The private key must be kept secret (i.e. out of the web-root of the authorization server). The authorization server also requires the public key.

If a passphrase has been used to generate private key it must be provided to the authorization server.

The public key should be distributed to any services (for example resource servers) that validate access tokens.

## Generating encryption keys

Encryption keys are used to encrypt authorization and refresh codes. The `AuthorizationServer` accepts two kinds of encryption keys, a `string` password or a `\Defuse\Crypto\Key` object from the [Secure PHP Encryption Library](https://github.com/defuse/php-encryption).

### string password

A `string` password can vary in strength depending on the password chosen. To turn it into a strong encryption key the [PBKDF2](https://en.wikipedia.org/wiki/PBKDF2) key derivation function is used.
This function derives an encryption key from a password and is slow by design. It uses a lot of CPU resources for a fraction of a second, applying key stretching to the password to reduce vulnerability to brute force attacks.

To generate a `string` password for the `AuthorizationServer`, you can run the following command in the terminal:

~~~ shell
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
~~~

### Key object

A `\Defuse\Crypto\Key` is a strong encryption key. This removes the need to use a slow key derivation function, reducing encryption and decryption times compared to using a `string` password.

A `Key` can be generated with the `generate-defuse-key` script. To generate a `Key` for the `AuthorizationServer` run the following command in the terminal:

~~~ shell
vendor/bin/generate-defuse-key
~~~

The `string` can be loaded as a `Key` with `Key::loadFromAsciiSafeString($string)`. For example:

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
