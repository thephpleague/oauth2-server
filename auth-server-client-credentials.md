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
* `client_id` with the client's ID
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
$clientRepository = new ClientRepository(); // instance of ClientRepositoryInterface
$scopeRepository = new ScopeRepository(); // instance of ScopeRepositoryInterface
$accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface

// Path to public and private keys
$privateKey = 'file://path/to/private.key';
//$privateKey = new CryptKey('file://path/to/private.key', 'passphrase'); // if private key has a pass phrase
$encryptionKey = 'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen'; // generate using base64_encode(random_bytes(32))

// Setup the authorization server
$server = new \League\OAuth2\Server\AuthorizationServer(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKey,
    $encryptionKey
);

// Enable the client credentials grant on the server
$server->enableGrantType(
    new \League\OAuth2\Server\Grant\ClientCredentialsGrant(),
    new \DateInterval('PT1H') // access tokens will expire after 1 hour
);
{% endhighlight %}

## Implementation

_Please note: These examples here demonstrate usage with the Slim Framework; Slim is not a requirement to use this library, you just need something that generates PSR7-compatible HTTP requests and responses._

The client will request an access token so create an `/access_token` endpoint.

{% highlight php %}
$app->post('/access_token', function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {

    /* @var \League\OAuth2\Server\AuthorizationServer $server */
    $server = $app->getContainer()->get(AuthorizationServer::class);

    try {
    
        // Try to respond to the request
        return $server->respondToAccessTokenRequest($request, $response);
        
    } catch (\League\OAuth2\Server\Exception\OAuthServerException $exception) {
    
        // All instances of OAuthServerException can be formatted into a HTTP response
        return $exception->generateHttpResponse($response);
        
    } catch (\Exception $exception) {
    
        // Unknown exception
        $body = new Stream('php://temp', 'r+');
        $body->write($exception->getMessage());
        return $response->withStatus(500)->withBody($body);
        
    }
});
{% endhighlight %}
