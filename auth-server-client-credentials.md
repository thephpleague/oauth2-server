---
layout: default
title: Authorization server with client credentials grant
permalink: /authorization-server/client-credentials-grant/
---

# Client credentials grant

This grant is similar to the resource owner credentials grant except only the client’s credentials are used to authenticate a request for an access token. Again this grant should only be allowed to be used by trusted clients.

This grant is suitable for machine-to-machine authentication, for example for use in a cron job which is performing maintenance tasks over an API. Another example would be a client making requests to an API that don’t require user’s permission.

## Setup

Wherever you initialize your objects, initialize a new instance of the authorization server and bind the storage interfaces and authorization code grant:

{% highlight php %}
// Your implementation of the required repositories
$clientRepository = new ClientRepository();
$accessTokenRepository = new AccessTokenRepository();
$scopeRepository = new ScopeRepository();

$privateKeyPath = 'file://path/to/private.key';
$publicKeyPath = 'file://path/to/public.key';

// Setup the authorization server
$server = new Server(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKeyPath,
    $publicKeyPath
);

// Enable the client credentials grant on the server with a token TTL of 1 hour
$server->enableGrantType(
    new ClientCredentialsGrant(),
    new \DateInterval('PT1H')
);
{% endhighlight %}

## Implementation

The client will request an access token so create an `/access_token` endpoint.

{% highlight php %}
$app->post('/access_token', function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {

    // Retrieve the authorization server from the DI container
    $server = $app->getContainer()->get(Server::class);
    
    try {
        // A successful response with an access token
        return $server->respondToRequest($request, $response);
        
    } catch (OAuthServerException $exception) {
        // A correctly formatted OAuth error response
        return $exception->generateHttpResponse($response);
        
    } catch (\Exception $exception) {
        // An unknown server error
        $body = new Stream('php://temp', 'r+');
        $body->write($exception->getMessage());
        return $response->withStatus(500)->withBody($body);
    }
});
{% endhighlight %}
