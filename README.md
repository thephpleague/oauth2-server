# PHP OAuth 2.0 Server

### :warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning:
### Security Notice 

### Please upgrade to version `>=5.1.6` (backwards compatible) or `6.x` (one tiny breaking change) to fix some potential security vulnerabilities - [visit this page for more information](https://oauth2.thephpleague.com/v5-security-improvements/)
### :warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning::warning:

[![Latest Version](http://img.shields.io/packagist/v/league/oauth2-server.svg?style=flat-square)](https://github.com/thephpleague/oauth2-server/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/thephpleague/oauth2-server/master.svg?style=flat-square)](https://travis-ci.org/thephpleague/oauth2-server)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/thephpleague/oauth2-server.svg?style=flat-square)](https://scrutinizer-ci.com/g/thephpleague/oauth2-server/code-structure)
[![Quality Score](https://img.shields.io/scrutinizer/g/thephpleague/oauth2-server.svg?style=flat-square)](https://scrutinizer-ci.com/g/thephpleague/oauth2-server)
[![Total Downloads](https://img.shields.io/packagist/dt/league/oauth2-server.svg?style=flat-square)](https://packagist.org/packages/league/oauth2-server)

`league/oauth2-server` is a standards compliant implementation of an [OAuth 2.0](https://tools.ietf.org/html/rfc6749) authorization server written in PHP which makes working with OAuth 2.0 trivial. You can easily configure an OAuth 2.0 server to protect your API with access tokens, or allow clients to request new access tokens and refresh them.

It supports out of the box the following grants:

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

This library was created by Alex Bilbie. Find him on Twitter at [@alexbilbie](https://twitter.com/alexbilbie).

## Requirements

The following versions of PHP are supported:

* PHP 5.6
* PHP 7.0
* PHP 7.1
* PHP 7.2

The `openssl` extension is also required.

## Documentation

The library documentation can be found at [https://oauth2.thephpleague.com](https://oauth2.thephpleague.com). 
You can contribute to the documentation in the [gh-pages branch](https://github.com/thephpleague/oauth2-server/tree/gh-pages/).

## Changelog

[See the project releases page](https://github.com/thephpleague/oauth2-server/releases)

## Contributing

Please see [CONTRIBUTING.md](https://github.com/thephpleague/oauth2-server/blob/master/CONTRIBUTING.md) and [CONDUCT.md](https://github.com/thephpleague/oauth2-server/blob/master/CONDUCT.md) for details.

## Support

Bugs and feature request are tracked on [GitHub](https://github.com/thephpleague/oauth2-server/issues).

If you have any questions about OAuth _please_ open a ticket here; please **don't** email the address below.

<a target='_blank' rel='nofollow' href='https://app.codesponsor.io/link/N2YMJcLBppt2Eg9E1jGu4gef/thephpleague/oauth2-server'>
  <img alt='Sponsor' width='888' height='68' src='https://app.codesponsor.io/embed/N2YMJcLBppt2Eg9E1jGu4gef/thephpleague/oauth2-server.svg' />
</a>

## Commercial Support

If you would like help implementing this library into your existing platform, or would be interested in OAuth advice or training for you and your team please get in touch with [Glynde Labs](https://glyndelabs.com).

## Security

If you discover any security related issues, please email `hello@alexbilbie.com` instead of using the issue tracker.

## License

This package is released under the MIT License. See the bundled [LICENSE](https://github.com/thephpleague/oauth2-server/blob/master/LICENSE) file for details.

## Credits

This code is principally developed and maintained by [Andy Millington](https://twitter.com/Sephster), [Brian 
Retterer](https://twitter.com/bretterer), and [Simon Hamp](https://twitter.com/simonhamp).

Between 2012 and 2017 this library was developed and maintained by [Alex Bilbie](https://alexbilbie.com/).

Special thanks to [all of these awesome contributors](https://github.com/thephpleague/oauth2-server/contributors).

Additional thanks go to the [Mozilla Secure Open Source Fund](https://wiki.mozilla.org/MOSS/Secure_Open_Source) for funding a security audit of this library.

The initial code was developed as part of the [Linkey](http://linkey.blogs.lincoln.ac.uk) project which was funded by [JISC](http://jisc.ac.uk) under the Access and Identity Management programme.
