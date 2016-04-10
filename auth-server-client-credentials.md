---
layout: default
title: Client credentials grant
permalink: /authorization-server/client-credentials-grant/
---

# Client credentials grant

This grant is suitable for machine-to-machine authentication, for example for use in a cron job which is performing maintenance tasks over an API. Another example would be a client making requests to an API that don’t require user’s permission.

## Flow

The client sends a POST request with following body parameters to the authorization server:

* `grant_type` with the value `client_credentials`
* `client_id` with the the client's ID
* `client_secret` with the client's secret
* `scope` with a space-delimited list of requested scope permissions.

The authorization server will respond with a JSON object containing the following properties:

* `token_type` with the value `Bearer`
* `expires_in` with an integer representing the TTL of the access token
* `access_token` a JWT signed with the authorization server's private key

## Setup

Wherever you initialize your objects, initialize a new instance of the authorization server and bind the storage interfaces and authorization code grant:

{% highlight php %}
// Init our repositories
$clientRepository = new ClientRepository();
$accessTokenRepository = new AccessTokenRepository();
$scopeRepository = new ScopeRepository();

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

// Enable the client credentials grant on the server with a token TTL of 1 hour
$server->enableGrantType(
    new \League\OAuth2\Server\Grant\ClientCredentialsGrant(),
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
