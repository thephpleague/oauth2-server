# PHP OAuth Framework

The goal of this project is to develop a standards compliant [OAuth 2](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-v2/) authorization server and resource server.

## Package Installation

The framework is provided as a Composer package which can be installed by adding the package to your composer.json file:

```javascript
{
	"require": {
		"lncd/OAuth2": "*"
	}
}
```

---

The library features 100% unit test code coverage. To run the tests yourself run `phpunit -c build/phpunit.xml`.

## Current Features

### Authorization Server

The authorization server is a flexible class and following core specification grants are implemented:

* authorization code ([section 4.1](http://tools.ietf.org/html/rfc6749#section-4.1))
* refresh token ([section 6](http://tools.ietf.org/html/rfc6749#section-6))
* client credentials ([section 2.3.1](http://tools.ietf.org/html/rfc6749#section-2.3.1))
* password (user credentials) ([section 4.3](http://tools.ietf.org/html/rfc6749#section-4.3))

An overview of the different OAuth 2.0 grants can be found at [http://alexbilbie.com/2013/02/a-guide-to-oauth-2-grants/](http://alexbilbie.com/2013/02/a-guide-to-oauth-2-grants/).

### Resource Server

The resource server allows you to secure your API endpoints by checking for a valid OAuth access token in the request and ensuring the token has the correct permission to access resources.


## Tutorials

A tutorial on how to use the authorization server can be found at [http://alexbilbie.com/2013/02/developing-an-oauth2-authorization-server/](http://alexbilbie.com/2013/02/developing-an-oauth2-authorization-server/).

A tutorial on how to use the resource server to secure an API server can be found at [http://alexbilbie.com/2013/02/securing-your-api-with-oauth-2/](http://alexbilbie.com/2013/02/securing-your-api-with-oauth-2/).

## Future Goals

### Authorization Server

* Support for [JSON web tokens](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-json-web-token/).
* Support for [SAML assertions](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-saml2-bearer/).

---

This code will be developed as part of the [Linkey](http://linkey.blogs.lincoln.ac.uk) project which has been funded by [JISC](http://jisc.ac.uk) under the Access and Identity Management programme.

This code was principally developed by [Alex Bilbie](http://alexbilbie.com/) ([Twitter](https://twitter.com/alexbilbie)|[Github](https://github.com/alexbilbie)).

Valuable contribtions have been made by the following:

* [Dan Horrigan](http://dandoescode.com) ([Twitter](https://twitter.com/dandoescode)|[Github](https://github.com/dandoescode))
* [Nick Jackson](http://nickjackson.me) ([Twitter](https://twitter.com/jacksonj04)|[Github](https://github.com/jacksonj04))
