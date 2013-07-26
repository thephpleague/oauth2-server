# PHP OAuth 2.0 Server

A standards compliant [OAuth 2.0](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-v2/) authorization server and resource server written in PHP.

## Package Installation

The framework is provided as a Composer package which can be installed by adding the package to your composer.json file:

```javascript
{
	"require": {
		"league/oauth2-server": "2.*"
	}
}
```

---

The library features 100% unit test code coverage. To run the tests yourself run `phpunit` from the project root.

## Current Features

### Authorization Server

The authorization server is a flexible class and the following core specification grants are implemented:

* authorization code ([section 4.1](http://tools.ietf.org/html/rfc6749#section-4.1))
* refresh token ([section 6](http://tools.ietf.org/html/rfc6749#section-6))
* client credentials ([section 2.3.1](http://tools.ietf.org/html/rfc6749#section-2.3.1))
* password (user credentials) ([section 4.3](http://tools.ietf.org/html/rfc6749#section-4.3))

An overview of the different OAuth 2.0 grants can be found in the wiki [https://github.com/php-loep/oauth2-server/wiki/Which-OAuth-2.0-grant-should-I-use%3F](https://github.com/php-loep/oauth2-server/wiki/Which-OAuth-2.0-grant-should-I-use%3F).

### Resource Server

The resource server allows you to secure your API endpoints by checking for a valid OAuth access token in the request and ensuring the token has the correct scope(s) (i.e. permissions) to access resources.

### Custom grants

Custom grants can be created easily by implementing an interface. Check out a guide here [https://github.com/php-loep/oauth2-server/wiki/Creating-custom-grants](https://github.com/php-loep/oauth2-server/wiki/Creating-custom-grants).

### PDO driver

If you are using MySQL and want to very quickly implement the library then all of the storage interfaces have been implemented with PDO classes. Check out the guide here [https://github.com/php-loep/oauth2-server/wiki/Using-the-PDO-storage-classes](https://github.com/php-loep/oauth2-server/wiki/Using-the-PDO-storage-classes).

## Tutorials and documentation

The wiki has lots of guides on how to use this library, check it out - [https://github.com/php-loep/oauth2-server/wiki](https://github.com/php-loep/oauth2-server/wiki).

A tutorial on how to use the authorization server can be found at [https://github.com/php-loep/oauth2-server/wiki/Developing-an-OAuth-2.0-authorization-server](https://github.com/php-loep/oauth2-server/wiki/Developing-an-OAuth-2.0-authorization-server).

A tutorial on how to use the resource server to secure an API server can be found at [https://github.com/php-loep/oauth2-server/wiki/Securing-your-API-with-OAuth-2.0](https://github.com/php-loep/oauth2-server/wiki/Securing-your-API-with-OAuth-2.0).

## Future Goals

### Authorization Server

* Support for [JSON web tokens](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-json-web-token/).
* Support for [SAML assertions](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-saml2-bearer/).

---

The initial code was developed as part of the [Linkey](http://linkey.blogs.lincoln.ac.uk) project which was funded by [JISC](http://jisc.ac.uk) under the Access and Identity Management programme.

This code is principally developed and maintained by [@alexbilbie](https://twitter.com/).


Credits
-------

* [Alex Bilbie](https://github.com/alexbilbie)
* [Dan Horrigan](https://github.com/dandoescode)
* [Nick Jackson](https://github.com/jacksonj04)
* [Michael Gooden](https://github.com/MichaelGooden)
* [Phil Sturgeon] (https://github.com/philsturgeon)
* [All contributors](https://github.com/php-loep/oauth2-server/contributors)

Changelog
---------

[See the changelog file](https://github.com/php-loep/oauth2-server/blob/master/CHANGELOG.md)

Contributing
------------

Please see [CONTRIBUTING](https://github.com/php-loep/oauth2-server/blob/master/CONTRIBUTING.md) for details.

Support
-------

Bugs and feature request are tracked on [GitHub](https://github.com/php-loep/oauth2-server/issues)


License
-------

oauth2-server is released under the MIT License. See the bundled
[LICENSE](https://github.com/php-loep/oauth2-server/blob/master/LICENSE) file for details.
