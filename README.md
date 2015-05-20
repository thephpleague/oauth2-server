# PHP OAuth 2.0 Server by [@alexbilbie](https://twitter.com/alexbilbie)

[![Latest Version](http://img.shields.io/packagist/v/league/oauth2-server.svg?style=flat-square)](https://github.com/thephpleague/oauth2-server/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/thephpleague/oauth2-server/master.svg?style=flat-square)](https://travis-ci.org/thephpleague/oauth2-server)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/thephpleague/oauth2-server.svg?style=flat-square)](https://scrutinizer-ci.com/g/thephpleague/oauth2-server/code-structure)
[![Quality Score](https://img.shields.io/scrutinizer/g/thephpleague/oauth2-server.svg?style=flat-square)](https://scrutinizer-ci.com/g/thephpleague/oauth2-server)
[![Total Downloads](https://img.shields.io/packagist/dt/league/oauth2-server.svg?style=flat-square)](https://packagist.org/packages/league/oauth2-server) [![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/thephpleague/oauth2-server?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)


A standards compliant [OAuth 2.0](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-v2/) authorization server and resource server written in PHP which makes working with OAuth 2.0 trivial. You can easily configure an OAuth 2.0 server to protect your API with access tokens, or allow clients to request new access tokens and refresh them.

It supports out of the box the following grants:

* Authorization code grant
* Client credentials grant
* Resource owner password credentials grant
* Refresh grant

You can also define your own grants.

In addition it supports the following token types:

* Bearer tokens
* MAC tokens
* JSON web tokens (coming soon)

You can also create you own tokens.


## Requirements

The following versions of PHP are supported:

* PHP 5.4
* PHP 5.5
* PHP 5.6
* HHVM

## Documentation

This library has [full documentation](http://oauth2.thephpleague.com), powered by [Jekyll](http://jekyllrb.com/).

Contribute to this documentation in the [gh-pages branch](https://github.com/thephpleague/oauth2-server/tree/gh-pages/).

## Changelog

[See the project releases page](https://github.com/thephpleague/oauth2-server/releases)

## Contributing

Please see [CONTRIBUTING](https://github.com/thephpleague/oauth2-server/blob/master/CONTRIBUTING.md) for details.

## Integration

- [CakePHP 3](https://github.com/uafrica/oauth-server)
- [Laravel](https://github.com/lucadegasperi/oauth2-server-laravel)

## Support

Bugs and feature request are tracked on [GitHub](https://github.com/thephpleague/oauth2-server/issues)

## Security

If you discover any security related issues, please email hello@alexbilbie.com instead of using the issue tracker.

## License

This package is released under the MIT License. See the bundled [LICENSE](https://github.com/thephpleague/oauth2-server/blob/master/LICENSE) file for details.

## Credits

This code is principally developed and maintained by [Alex Bilbie](https://twitter.com/alexbilbie).

Special thanks to:

* [Dan Horrigan](https://github.com/dandoescode)
* [Nick Jackson](https://github.com/jacksonj04)
* [Michael Gooden](https://github.com/MichaelGooden)
* [Phil Sturgeon](https://github.com/philsturgeon)
* [and all the other contributors](https://github.com/thephpleague/oauth2-server/contributors)

The initial code was developed as part of the [Linkey](http://linkey.blogs.lincoln.ac.uk) project which was funded by [JISC](http://jisc.ac.uk) under the Access and Identity Management programme.
