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
$userRepository = new UserRepository();

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
        $userRepository,
        new \DateInterval('PT10M')
    ),
    new \DateInterval('PT1H')
);
{% endhighlight %}

## Implementation

The client will request an access token so create an `/oauth2` endpoint.

{% highlight php %}
$app->post('/oauth2', function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {

    /* @var \League\OAuth2\Server\Server $server */
    $server = $app->getContainer()->get(Server::class);

    // Try to respond to the request
    try {
        return $server->respondToRequest($request, $response);

    } catch (\League\OAuth2\Server\Exception\OAuthServerException $exception) {
        return $exception->generateHttpResponse($response);

    } catch (\Exception $exception) {
        $body = new Stream('php://temp', 'r+');
        $body->write($exception->getMessage());
        return $response->withStatus(500)->withBody($body);
    }
});
{% endhighlight %}

## Modify the login and authorize pages

You can easily modify the HTML pages used by the authorization server. The library comes with built-in support for Twig, Smarty, Mustache and Plates templates.

The default implementation uses `league/plates` and has some [very basic HTML templates](https://github.com/thephpleague/oauth2-server/tree/V5-WIP/src/TemplateRenderer/DefaultTemplates).

The login template has the following variable available:

* `error` (null or a string) - Set if there was an error with the login

The form inputs must be called `username` and `password` and must be POSTed.

The authorize template has the following variable available:

* `client` - The name of the client the user is authorizing
* `scopes` - An array of ScopeEntityInterface. Use `getIdentifier` to get a string you can print

The form must be POSTed with an input named `action` with the value `approve` if the user approves the client.

### Using Plates with custom templates

{% highlight php %}
$renderer = new \League\OAuth2\Server\TemplateRenderer\PlatesRenderer(
    new Engine('/path/to/templates'),
    'login_template_name',
    'authorize_template_name'
);
$authCodeGrant->setTemplateRenderer($renderer);
{% endhighlight %}

### Using Twig with custom templates

{% highlight php %}
$renderer = new \League\OAuth2\Server\TemplateRenderer\TwigRenderer(
    $environment, // instance of Twig_Environment
    'login_template_name',
    'authorize_template_name'
);
$authCodeGrant->setTemplateRenderer($renderer);
{% endhighlight %}

### Using Smarty with custom templates

{% highlight php %}
$renderer = new \League\OAuth2\Server\TemplateRenderer\SmartyRenderer(
    $smarty, // instance of \Smarty
    'login_template_name',
    'authorize_template_name'
);
$authCodeGrant->setTemplateRenderer($renderer);
{% endhighlight %}

### Using Mustache with custom templates

{% highlight php %}
$renderer = new \League\OAuth2\Server\TemplateRenderer\MustacheRenderer(
    $engine, // instance of \Mustache_Engine
    'login_template_name',
    'authorize_template_name'
);
$authCodeGrant->setTemplateRenderer($renderer);
{% endhighlight %}
