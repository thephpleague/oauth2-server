# PHP OAuth 2.0 Server

[![Latest Version](http://img.shields.io/packagist/v/league/oauth2-server.svg?style=flat-square)](https://github.com/thephpleague/oauth2-server/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/thephpleague/oauth2-server/master.svg?style=flat-square)](https://travis-ci.org/thephpleague/oauth2-server)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/thephpleague/oauth2-server.svg?style=flat-square)](https://scrutinizer-ci.com/g/thephpleague/oauth2-server/code-structure)
[![Quality Score](https://img.shields.io/scrutinizer/g/thephpleague/oauth2-server.svg?style=flat-square)](https://scrutinizer-ci.com/g/thephpleague/oauth2-server)
[![Total Downloads](https://img.shields.io/packagist/dt/league/oauth2-server.svg?style=flat-square)](https://packagist.org/packages/league/oauth2-server)
[![PHPStan](https://img.shields.io/badge/PHPStan-enabled-brightgreen.svg?style=flat-square)](https://github.com/phpstan/phpstan)

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

This library was created by Alex Bilbie. Find him on Twitter at [@alexbilbie](https://twitter.com/alexbilbie).

## Requirements

The following versions of PHP are supported:

* PHP 7.1
* PHP 7.2
* PHP 7.3

The `openssl` and `json` extensions are also required.

All HTTP messages passed to the server should be [PSR-7 compliant](https://www.php-fig.org/psr/psr-7/). This ensures interoperability with other packages and frameworks.

## Installation

```
composer require league/oauth2-server
```

## Documentation

The library documentation can be found at [https://oauth2.thephpleague.com](https://oauth2.thephpleague.com).
You can contribute to the documentation in the [gh-pages branch](https://github.com/thephpleague/oauth2-server/tree/gh-pages/).

## Testing

The library uses [PHPUnit](https://phpunit.de/) for unit tests and [PHPStan](https://github.com/phpstan/phpstan) for static analysis of the code.

```
vendor/bin/phpunit
vendor/bin/phpstan analyse -l 7 -c phpstan.neon src tests
```

## Continous Integration

We use [Travis CI](https://travis-ci.org/), [Scrutinizer](https://scrutinizer-ci.com/), and [StyleCI](https://styleci.io/) for continuous integration. Check out [our](https://github.com/thephpleague/oauth2-server/blob/master/.travis.yml) [configuration](https://github.com/thephpleague/oauth2-server/blob/master/.scrutinizer.yml) [files](https://github.com/thephpleague/oauth2-server/blob/master/.styleci.yml) if you'd like to know more.

## Community Integrations

* [Drupal](https://www.drupal.org/project/simple_oauth)
* [Laravel Passport](https://github.com/laravel/passport)
* [OAuth 2 Server for CakePHP 3](https://github.com/uafrica/oauth-server)
* [OAuth 2 Server for Expressive](https://github.com/zendframework/zend-expressive-authentication-oauth2)
* [Trikoder OAuth 2 Bundle (Symfony)](https://github.com/trikoder/oauth2-bundle)

## Changelog

See the [project changelog](https://github.com/thephpleague/oauth2-server/blob/master/CHANGELOG.md)

## Contributing

Contributions are always welcome. Please see [CONTRIBUTING.md](https://github.com/thephpleague/oauth2-server/blob/master/CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](https://github.com/thephpleague/oauth2-server/blob/master/CODE_OF_CONDUCT.md) for details.

## Support

Bugs and feature request are tracked on [GitHub](https://github.com/thephpleague/oauth2-server/issues).

If you have any questions about OAuth _please_ open a ticket here; please **don't** email the address below.

## Security

If you discover any security related issues, please email `andrew@noexceptions.io` instead of using the issue tracker.

## License

This package is released under the MIT License. See the bundled [LICENSE](https://github.com/thephpleague/oauth2-server/blob/master/LICENSE) file for details.

## Credits

This code is principally developed and maintained by [Andy Millington](https://twitter.com/Sephster).

Between 2012 and 2017 this library was developed and maintained by [Alex Bilbie](https://alexbilbie.com/).

PHP OAuth 2.0 Server is one of many packages provided by The PHP League. To find out more, please visit [our website](https://thephpleague.com).

Special thanks to [all of these awesome contributors](https://github.com/thephpleague/oauth2-server/contributors).

Additional thanks go to the [Mozilla Secure Open Source Fund](https://wiki.mozilla.org/MOSS/Secure_Open_Source) for funding a security audit of this library.

The initial code was developed as part of the [Linkey](http://linkey.blogs.lincoln.ac.uk) project which was funded by [JISC](http://jisc.ac.uk) under the Access and Identity Management programme.
