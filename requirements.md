---
layout: default
title: Requirements
permalink: /requirements/
---

# Requirements

In order to prevent man-in-the-middle attacks, the authorization server MUST require the use of TLS with server authentication as defined by [RFC2818](https://tools.ietf.org/html/rfc2818) for any request sent to the authorization and token endpoints.  The client MUST validate the authorization server's TLS certificate as defined by [RFC6125](https://tools.ietf.org/html/rfc6125) and in accordance with its requirements for server identity authentication.

This library uses key cryptography in order to encrypt and decrypt, as well as verify the integrity of signatures. See the [installation](/installation) page for details on how to generate the keys.

The following versions of PHP are supported:

* PHP 7.2
* PHP 7.3
* PHP 7.4
* PHP 8.0

The `openssl` and `json` extensions are also required.

All HTTP messages passed to the server should be [PSR-7 compliant](https://www.php-fig.org/psr/psr-7/). This ensures interoperability between other packages and frameworks.
