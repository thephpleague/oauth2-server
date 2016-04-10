---
layout: default
title: Refresh token grant
permalink: /authorization-server/refresh-token-grant/
---

# Refresh token grant

Access tokens eventually expire; however some grants respond with a refresh token which enables the client to refresh the access token.

## Flow

The client sends a POST request with following body parameters to the authorization server:

* `grant_type` with the value `refresh_token`
* `client_id` with the the client's ID
* `client_secret` with the client's secret
* `scope` with a space-delimited list of requested scope permissions. This is optional; if not sent the original scopes will be used, otherwise you can request a reduced set of scopes.

The authorization server will respond with a JSON object containing the following properties:

* `token_type` with the value `Bearer`
* `expires_in` with an integer representing the TTL of the access token
* `access_token` a new JWT signed with the authorization server's private key
* `refresh_token` an encrypted payload that can be used to refresh the access token when it expires

## Setup

Wherever you initialize your objects, initialize a new instance of the authorization server and bind the storage interfaces and authorization code grant:

{% highlight php %}
// Init our repositories
$clientRepository = new ClientRepository();
$accessTokenRepository = new AccessTokenRepository();
$scopeRepository = new ScopeRepository();
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

// Enable the refresh token grant on the server with a token TTL of 1 hour
$server->enableGrantType(
    new \League\OAuth2\Server\Grant\RefreshTokenGrant($refreshTokenRepository),
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
