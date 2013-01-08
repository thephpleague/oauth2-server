# PHP OAuth Framework

The goal of this project is to develop a standards compliant [OAuth 2](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-v2/) authentication server, resource server and client library with support for a major OAuth 2 providers.

## Package Installation

The framework is provided as a Composer package which can be installed by adding the package to your composer.json file:

```javascript
{
	"require": {
		"lncd\OAuth2": "*"
	}
}
```

## Package Integration

Check out the [wiki](https://github.com/lncd/OAuth2/wiki)

## Current Features

### Authentication Server

The authentication server is a flexible class that supports the following grants:

* authentication code
* refresh token
* client credentials
* password (user credentials)

### Resource Server

The resource server allows you to secure your API endpoints by checking for a valid OAuth access token in the request and ensuring the token has the correct permission to access resources.




## Future Goals

### Authentication Server

* Support for [JSON web tokens](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-json-web-token/).
* Support for [SAML assertions](http://tools.ietf.org/wg/oauth/draft-ietf-oauth-saml2-bearer/).

### Client support

* Merge in https://github.com/philsturgeon/codeigniter-oauth2

---

This code will be developed as part of the [Linkey](http://linkey.blogs.lincoln.ac.uk) project which has been funded by [JISC](http://jisc.ac.uk) under the Access and Identity Management programme.