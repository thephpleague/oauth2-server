# PHP OAuth 2.0 Server

[![Latest Version](http://img.shields.io/packagist/v/league/oauth2-server.svg?style=flat-square)](https://github.com/thephpleague/oauth2-server/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/thephpleague/oauth2-server/master.svg?style=flat-square)](https://travis-ci.org/thephpleague/oauth2-server)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/thephpleague/oauth2-server.svg?style=flat-square)](https://scrutinizer-ci.com/g/thephpleague/oauth2-server/code-structure)
[![Quality Score](https://img.shields.io/scrutinizer/g/thephpleague/oauth2-server.svg?style=flat-square)](https://scrutinizer-ci.com/g/thephpleague/oauth2-server)
[![Total Downloads](https://img.shields.io/packagist/dt/league/oauth2-server.svg?style=flat-square)](https://packagist.org/packages/league/oauth2-server)

`league/oauth2-server` is a a standards compliant implementation of an [OAuth 2.0](https://tools.ietf.org/html/rfc6749) authorization server written in PHP which makes working with OAuth 2.0 trivial. You can easily configure an OAuth 2.0 server to protect your API with access tokens, or allow clients to request new access tokens and refresh them.

It supports out of the box the following grants:

* Authorization code grant
* Implicit grant
* Client credentials grant
* Resource owner password credentials grant
* Refresh grant

This library was created by Alex Bilbie. Find him on Twitter at [@alexbilbie](https://twitter.com/alexbilbie).

## Requirements

The following versions of PHP are supported:

* PHP 5.5 (>=5.5.9)
* PHP 5.6
* PHP 7.0
* HHVM

The `openssl` extension is also required.

## Documentation

The library documentation can be found at [https://oauth2.thephpleague.com](https://oauth2.thephpleague.com). 
You can contribute to the documentation in the [gh-pages branch](https://github.com/thephpleague/oauth2-server/tree/gh-pages/).

## Changelog

[See the project releases page](https://github.com/thephpleague/oauth2-server/releases)

## Contributing

Please see [CONTRIBUTING.md](https://github.com/thephpleague/oauth2-server/blob/master/CONTRIBUTING.md) and [CONDUCT.md](https://github.com/thephpleague/oauth2-server/blob/master/CONDUCT.md) for details.

## Integration

- [CakePHP 3](https://github.com/uafrica/oauth-server)
- [Laravel](https://github.com/lucadegasperi/oauth2-server-laravel)

## Support

Bugs and feature request are tracked on [GitHub](https://github.com/thephpleague/oauth2-server/issues).

If you have any questions about OAuth _please_ open a ticket here; please **don't** email the address below.

## Security

If you discover any security related issues, please email hello@alexbilbie.com instead of using the issue tracker.

## License

This package is released under the MIT License. See the bundled [LICENSE](https://github.com/thephpleague/oauth2-server/blob/master/LICENSE) file for details.

## Credits

This code is principally developed and maintained by [Alex Bilbie](https://twitter.com/alexbilbie).

Special thanks to [all of these awesome contributors](https://github.com/thephpleague/oauth2-server/contributors)

The initial code was developed as part of the [Linkey](http://linkey.blogs.lincoln.ac.uk) project which was funded by [JISC](http://jisc.ac.uk) under the Access and Identity Management programme.
