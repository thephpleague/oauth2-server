# Example implementations (via [`Slim 3`](https://github.com/slimphp/Slim/tree/3.x))

## Installation

0. Run `composer install` in this directory to install dependencies
0. Create a private key `openssl genrsa -out private.key 2048`
0. Export the public key `openssl rsa -in private.key -pubout > public.key`
0. Start local PHP server `php -S 127.0.0.1:4444 -t public/`

## Testing the client credentials grant example

Send the following cURL request:

```
curl -X "POST" "http://localhost:4444/client_credentials.php/access_token" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Accept: 1.0" \
	--data-urlencode "grant_type=client_credentials" \
	--data-urlencode "client_id=myawesomeapp" \
	--data-urlencode "client_secret=abc123" \
	--data-urlencode "scope=basic email"
```

## Testing the password grant example

Send the following cURL request:

```
curl -X "POST" "http://localhost:4444/password.php/access_token" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Accept: 1.0" \
	--data-urlencode "grant_type=password" \
	--data-urlencode "client_id=myawesomeapp" \
	--data-urlencode "client_secret=abc123" \
	--data-urlencode "username=alex" \
	--data-urlencode "password=whisky" \
	--data-urlencode "scope=basic email"
```

## Testing the refresh token grant example

Send the following cURL request. Replace `{{REFRESH_TOKEN}}` with a refresh token from another grant above:

```
curl -X "POST" "http://localhost:4444/refresh_token.php/access_token" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Accept: 1.0" \
	--data-urlencode "grant_type=refresh_token" \
	--data-urlencode "client_id=myawesomeapp" \
	--data-urlencode "client_secret=abc123" \
	--data-urlencode "refresh_token={{REFRESH_TOKEN}}"
```

## Testing the device authorization grant example

Send the following cURL request. This will return a device code which can be exchanged for an access token.

```
curl -X "POST" "http://localhost:4444/device_code.php/device_authorization" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Accept: 1.0" \
	--data-urlencode "client_id=myawesomeapp" \
	--data-urlencode "client_secret=abc123" \
	--data-urlencode "scope=basic email"
```

We have set up the example so that a user ID is already associated with the device code. In a production application you
would implement an authorization view to allow a user to authorize the device.

Issue the following cURL request to exchange your device code for an access token. Replace `{{DEVICE_CODE}}` with the
device code returned from your first cURL post:

```
curl -X "POST" "http://localhost:4444/device_code.php/access_token" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Accept: 1.0" \
	--data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
	--data-urlencode "device_code={{DEVICE_CODE}}" \
	--data-urlencode "client_id=myawesomeapp" \
	--data-urlencode "client_secret=abc123"
```

## Testing the token revocation example

Send the following cURL request. Replace `{{TOKEN}}` with an access token or a refresh token from another grant above:

```
curl -X "POST" "http://localhost:4444/token_revocation.php/revoke_token" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Accept: 1.0" \
	--data-urlencode "client_id=myawesomeapp" \
	--data-urlencode "client_secret=abc123" \
	--data-urlencode "token_type_hint=access_token" \
	--data-urlencode "token={{TOKEN}}"
```

## Testing the token introspection example

Send the following cURL request. Replace `{{TOKEN}}` with an access token or a refresh token from another grant above:

```
curl -X "POST" "http://localhost:4444/token_introspection.php/introspect_token" \
	-H "Content-Type: application/x-www-form-urlencoded" \
	-H "Accept: 1.0" \
	--data-urlencode "client_id=myawesomeapp" \
	--data-urlencode "client_secret=abc123" \
	--data-urlencode "token_type_hint=access_token" \
	--data-urlencode "refresh_token={{TOKEN}}"
```
