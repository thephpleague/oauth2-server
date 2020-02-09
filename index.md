---
layout: default
title: Introduction
---

# Introduction

[![Author](http://img.shields.io/badge/author-@alexbilbie-red.svg?style=flat-square)](https://twitter.com/alexbilbie)
[![Source Code](http://img.shields.io/badge/source-thephpleague%2Foauth2--server-blue.svg?style=flat-square)](https://github.com/thephpleague/oauth2-server)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/thephpleague/oauth2-server/master.svg?style=flat-square)](https://travis-ci.org/thephpleague/oauth2-server)
[![Total Downloads](https://img.shields.io/packagist/dt/league/oauth2-server.svg?style=flat-square)](https://packagist.org/packages/league/oauth2-server)

`league/oauth2-server` is a standards compliant implementation of an [OAuth 2.0](https://tools.ietf.org/html/rfc6749) authorization server written in PHP which makes working with OAuth 2.0 trivial. You can easily configure an OAuth 2.0 server to protect your API with access tokens, or allow clients to request new access tokens and refresh them.

Out of the box it supports the following grants:

* Authorization code grant
* Implicit grant
* Client credentials grant
* Resource owner password credentials grant
* Refresh grant

The following RFCs are implemented:

* [RFC6749 "OAuth 2.0"](https://tools.ietf.org/html/rfc6749)
* [RFC6750 " The OAuth 2.0 Authorization Framework: Bearer Token Usage"](https://tools.ietf.org/html/rfc6750)
* [RFC7519 "JSON Web Token (JWT)"](https://tools.ietf.org/html/rfc7519)
* [RFC7636 "Proof Key for Code Exchange by OAuth Public Clients"](https://tools.ietf.org/html/rfc7636)

<!--
You can also easily make your own [custom grants]().
-->

This library was created by Alex Bilbie. Find him on Twitter at [@alexbilbie](https://twitter.com/alexbilbie).

## Changelog

Please see the [project's changelog](https://github.com/thephpleague/oauth2-server/blob/master/CHANGELOG.md) for a complete history of changes to this library.

The latest release is [![GitHub tag](https://img.shields.io/github/tag/thephpleague/oauth2-server.svg)](https://github.com/thephpleague/oauth2-server/releases)

## Support

Please ask questions on the [Github issues page](https://github.com/thephpleague/oauth2-server/issues).

For commercial support and custom implementations please visit [Glynde Labs](https://glyndelabs.com).
