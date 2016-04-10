---
layout: default
title: Authorization code grant
permalink: /authorization-server/auth-code-grant/
---

# Authorization code grant

The authorization code grant should be very familiar if you've ever signed into a web app using your Facebook or Google account.

## Flow

### Part One

The client will redirect the user to the authorization server with the following parameters in the query string:

* `response_type` with the value `code`
* `client_id` with the client identifier
* `redirect_uri` with the client redirect URI. This parameter is optional, but if not send the user will be redirected to a pre-registered redirect URI.
* `scope` a space delimited list of scopes
* `state` with a CSRF token. This parameter is optional but highly recommended.

All of these parameters will be validated by the authorization server.

The user will then be asked to login to the authorization server and approve the client.

If the user approves the client they will be redirected back to the authorization server with the following parameters in the query string:

* `code` with the authorization code
* `state` with the state parameter sent in the original request

### Part Two

The client will now send a POST request to the authorization server with the following parameters:

* `grant_type` with the value of `authorization_code`
* `client_id` with the client identifier
* `client_secret` with the client secret
* `redirect_uri` with the same redirect URI the user was redirect back to
* `code` with the authorization code from the query string (remember to url decode it first)

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
$scopeRepository = new ScopeRepository();
$accessTokenRepository = new AccessTokenRepository();
$authCodeRepository = new AuthCodeRepository();
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

// Enable the authentication code grant on the server with a token TTL of 1 hour
$server->enableGrantType(
    new \League\OAuth2\Server\Grant\AuthCodeGrant(
        $authCodeRepository,
        $refreshTokenRepository,
        new \DateInterval('PT10M')
    ),
    new \DateInterval('PT1H')
);
{% endhighlight %}

## Implementation

The client will redirect the user to an authorization endpoint.

{% highlight php %}
$app->get('/authorize', function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {
    /* @var \League\OAuth2\Server\Server $server */
    $server = $app->getContainer()->get(Server::class);
    try {
        // Validate the HTTP request and return an AuthorizationRequest object.
        $authRequest = $server->validateAuthorizationRequest($request);
        
        // The auth request object can be serialized and saved into a user's session.
        // You will probably want to redirect the user at this point to a login endpoint.
        
        // Once the user has logged in set the user on the AuthorizationRequest
        $authRequest->setUser(new UserEntity());
        
        // At this point you should redirect the user to an authorization page.
        // This form will ask the user to approve the client and the scopes requested.
        
        // Once the user has approved or denied the client update the status
        // (true = approved, false = denied)
        $authRequest->setAuthorizationApproved(true);
        
        // Return the HTTP redirect response
        return $server->completeAuthorizationRequest($authRequest, $response);
        
    } catch (OAuthServerException $exception) {
        return $exception->generateHttpResponse($response);
        
    } catch (\Exception $exception) {
        $body = new Stream('php://temp', 'r+');
        $body->write($exception->getMessage());
        return $response->withStatus(500)->withBody($body);
    }
});
{% endhighlight %}

The client will request an access token using an authorization code so create an `/access_token` endpoint.

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

