---
layout: default
title: Implicit grant
permalink: /authorization-server/implicit-grant/
---

# Implicit grant

The implicit grant is similar to the authorization code grant with two distinct differences. 

It is intended to be used for user-agent-based clients (e.g. single page web apps) that can't keep a client secret because all of the application code and storage is easily accessible.

Secondly instead of the authorization server returning an authorization code which is exchanged for an access token, the authorization server returns an access token.

## Flow
    
The client will redirect the user to the authorization server with the following parameters in the query string:

* `response_type` with the value `token`
* `client_id` with the client identifier
* `redirect_uri` with the client redirect URI. This parameter is optional, but if not send the user will be redirected to a pre-registered redirect URI.
* `scope` a space delimited list of scopes
* `state` with a CSRF token. This parameter is optional but highly recommended.

All of these parameters will be validated by the authorization server.

The user will then be asked to login to the authorization server and approve the client.

If the user approves the client they will be redirected back to the authorization server with the following parameters in the query string:

* `token_type` with the value `Bearer`
* `expires_in` with an integer representing the TTL of the access token
* `access_token` a JWT signed with the authorization server's private key

****Note**** this grant does not return a refresh token.

## Setup

Wherever you initialize your objects, initialize a new instance of the authorization server and bind the storage interfaces and authorization code grant:

{% highlight php %}
// Init our repositories
$clientRepository = new ClientRepository();
$scopeRepository = new ScopeRepository();
$accessTokenRepository = new AccessTokenRepository();
$userRepository = new UserRepository();

// Path to public and private keys
$privateKeyPath = 'file://path/to/private.key';
$publicKeyPath = 'file://path/to/public.key';
        
// Setup the authorization server
$server = new \League\OAuth2\Server\Server(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKeyPath,
    $publicKeyPath
);

// Enable the implicit grant on the server with a token TTL of 1 hour
$server->enableGrantType(
    new ImplicitGrant($userRepository),
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
$implicitGrant->setTemplateRenderer($renderer);
{% endhighlight %}

### Using Twig with custom templates

{% highlight php %}
$renderer = new \League\OAuth2\Server\TemplateRenderer\TwigRenderer(
    $environment, // instance of Twig_Environment
    'login_template_name',
    'authorize_template_name'
);
$implicitGrant->setTemplateRenderer($renderer);
{% endhighlight %}

### Using Smarty with custom templates

{% highlight php %}
$renderer = new \League\OAuth2\Server\TemplateRenderer\SmartyRenderer(
    $smarty, // instance of \Smarty
    'login_template_name',
    'authorize_template_name'
);
$implicitGrant->setTemplateRenderer($renderer);
{% endhighlight %}

### Using Mustache with custom templates

{% highlight php %}
$renderer = new \League\OAuth2\Server\TemplateRenderer\MustacheRenderer(
    $engine, // instance of \Mustache_Engine
    'login_template_name',
    'authorize_template_name'
);
$implicitGrant->setTemplateRenderer($renderer);
{% endhighlight %}