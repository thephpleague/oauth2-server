# PHP OAuth 2.0 Server

[![Latest Stable Version](https://poser.pugx.org/league/oauth2-server/v/stable.png)](https://packagist.org/packages/league/oauth2-server) [![Coverage Status](https://coveralls.io/repos/thephpleague/oauth2-server/badge.png?branch=master)](https://coveralls.io/r/thephpleague/oauth2-server?branch=master) [![Total Downloads](https://poser.pugx.org/league/oauth2-server/downloads.png)](https://packagist.org/packages/league/oauth2-server) [![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/thephpleague/oauth2-server/trend.png)](https://bitdeli.com/free "Bitdeli Badge")


A standards compliant [OAuth 2.0](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-v2/) authorization server and resource server written in PHP.

## Package Installation

The framework is provided as a Composer package which can be installed by adding the package to your `composer.json` file:

```javascript
{
	"require": {
		"league/oauth2-server": "3.*"
	}
}
```

### Framework Integrations

* [Laravel Service Provider](https://packagist.org/packages/lucadegasperi/oauth2-server-laravel) by @lucadegasperi
* [Laravel Eloquent implementation](https://github.com/ScubaClick/scubaclick-oauth2) by @ScubaClick (under development)

---

The library features 100% unit test code coverage. To run the tests yourself run `phpunit` from the project root.

[![Build Status](https://travis-ci.org/thephpleague/oauth2-server.png?branch=master)](https://travis-ci.org/thephpleague/oauth2-server) [master]

[![Build Status](https://travis-ci.org/thephpleague/oauth2-server.png?branch=develop)](https://travis-ci.org/thephpleague/oauth2-server) [develop]


## Current Features

### Authorization Server

The authorization server is a flexible class and the following core specification grants are implemented:

* authorization code ([section 4.1](http://tools.ietf.org/html/rfc6749#section-4.1))
* refresh token ([section 6](http://tools.ietf.org/html/rfc6749#section-6))
* client credentials ([section 2.3.1](http://tools.ietf.org/html/rfc6749#section-2.3.1))
* password (user credentials) ([section 4.3](http://tools.ietf.org/html/rfc6749#section-4.3))

### Resource Server

The resource server allows you to secure your API endpoints by checking for a valid OAuth access token in the request and ensuring the token has the correct scope(s) (i.e. permissions) to access resources.

### Custom grants

Custom grants can be created easily by implementing an interface.

## Changelog

[See the project releases page](https://github.com/thephpleague/oauth2-server/releases)

## Contributing

Please see [CONTRIBUTING](https://github.com/thephpleague/oauth2-server/blob/master/CONTRIBUTING.md) for details.

## Support

Bugs and feature request are tracked on [GitHub](https://github.com/thephpleague/oauth2-server/issues)

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

[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/thephpleague/oauth2-server/trend.png)](https://bitdeli.com/free "Bitdeli Badge")
