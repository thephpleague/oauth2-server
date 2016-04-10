---
layout: default
title: Resource owner password credentials grant
permalink: /authorization-server/resource-owner-password-credentials-grant/
---

# Resource owner password credentials grant

This grant is a great user experience for <u>trusted</u> first party clients both on the web and in native applications.

## Flow

The client will ask the user for their authorization credentials (ususally a username and password).

The client then sends a POST request with following body parameters to the authorization server:

* `grant_type` with the value `password`
* `client_id` with the the client's ID
* `client_secret` with the client's secret
* `scope` with a space-delimited list of requested scope permissions.
* `username` with the user's username
* `password` with the user's password

The authorization server will respond with a JSON object containing the following properties:

* `token_type` with the value `Bearer`
* `expires_in` with an integer representing the TTL of the access token
* `access_token` a JWT signed with the authorization server's private key
* `refresh_token` an encrypted payload that can be used to refresh the access token when it expires.

## Setup

Wherever you initialize your objects, initialize a new instance of the authorization server and bind the storage interfaces and authorization code grant:

{% highlight php %}
// Init our repositories
$clientRepository = new ClientRepository();
$accessTokenRepository = new AccessTokenRepository();
$scopeRepository = new ScopeRepository();
$userRepository = new UserRepository();
$refreshTokenRepository = new RefreshTokenRepository();

// Path to public and private keys
$privateKey = 'file://path/to/private.key';
// Private key with passphrase if needed
//$privateKey = new CryptKey('file://path/to/private.key', 'passphrase');
$publicKey = 'file://path/to/public.key';

// Setup the authorization server
$server = new \League\OAuth2\Server\Server(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKey,
    $publicKey
);

// Enable the password grant on the server with an access token TTL of 1 hour
$server->enableGrantType(
    new \League\OAuth2\Server\Grant\PasswordGrant(
        $userRepository,
        $refreshTokenRepository
    ),
    new \DateInterval('PT1H')
);
{% endhighlight %}

## Implementation

The client will request an access token so create an `/access_token` endpoint.

{% highlight php %}
$app->post('/access_token', function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {

    /* @var \League\OAuth2\Server\Server $server */
    $server = $app->getContainer()->get(Server::class);

    // Try to respond to the request
    try {
        return $server->respondToAccessTokenRequest($request, $response);

    } catch (\League\OAuth2\Server\Exception\OAuthServerException $exception) {
        return $exception->generateHttpResponse($response);

    } catch (\Exception $exception) {
        $body = new Stream('php://temp', 'r+');
        $body->write($exception->getMessage());
        return $response->withStatus(500)->withBody($body);
    }
});
{% endhighlight %}
