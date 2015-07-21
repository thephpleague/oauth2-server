---
layout: default
title: Authorization server with authorization code grant
permalink: /authorization-server/auth-code-grant/
---

# Authorization server with authorization code grant

## Setup

Wherever you intialise your objects, initialize a new instance of the authorization server and bind the storage interfaces and authorization code grant:

~~~ php
$server = new \League\OAuth2\Server\AuthorizationServer;

$server->setSessionStorage(new Storage\SessionStorage);
$server->setAccessTokenStorage(new Storage\AccessTokenStorage);
$server->setClientStorage(new Storage\ClientStorage);
$server->setScopeStorage(new Storage\ScopeStorage);
$server->setAuthCodeStorage(new Storage\AuthCodeStorage);

$authCodeGrant = new \League\OAuth2\Server\Grant\AuthCodeGrant();
$server->addGrantType($authCodeGrant);
~~~


## Implementation

Create a route which will respond to a request to `/oauth` which is where the client will redirect the user to.

~~~ php
$router->get('/oauth', function (Request $request) use ($server) {

    // First ensure the parameters in the query string are correct
    try {

        $authParams = $server->getGrantType('authorization_code')->checkAuthorizeParams();

    } catch (\Exception $e) {

        if ($e->shouldRedirect()) {
            return new Response('', 302, [
                'Location'  =>  $e->getRedirectUri()
            ]);
        }

        return new Response(
            json_encode([
                'error'     =>  $e->errorType,
                'message'   =>  $e->getMessage()
            ]),
            $e->httpStatusCode, // All of the library's exception classes have a status code specific to the error
            $e->getHttpHeaders() // Some exceptions have headers which need to be sent
        );

    }

    // Everything is okay, save $authParams to the a session and redirect the user to sign-in

    return new Response('', 302, [
        'Location'  =>  '/signin'
    ]);

});
~~~



The user is redirected to a sign-in screen. If the user is not signed in then sign them in.

~~~ php
$router->get('/signin', function (Request $request) use ($server) {

    if ($user) {

        $response = new Response('', 302, [
            'Location'  =>  '/authorize'
        ]);

        return $response;

    } else {

        // Logic here to show the a sign-in form and sign the user in

    }

});
~~~


The final part is to show a web page that tells the user the name of the client, the scopes requested and two buttons, an "Approve" button and a "Deny" button.

View:

~~~ php
// Authorize view
<h1><?= $authParams['client']->getName() ?> would like to access:</h1>

<ul>
    <?php foreach ($authParams['scopes'] as $scope): ?>
        <li>
            <?= $scope->getName() ?>: <?= $scope->getDescription() ?>
        </li>
    <?= endforeach; ?>
</ul>

<form method="post">
    <input type="submit" value="Approve" name="authorization">
    <input type="submit" value="Deny" name="authorization">
</form>
~~~




Route:

~~~ php
$router->get('/authorize', function (Request $request) use ($server) {

    if (!isset($_POST['authorization'])) {
        // show form
    }

    // If the user authorizes the request then redirect the user back with an authorization code

    if ($_POST['authorization'] === 'Approve') {
        $redirectUri = $server->getGrantType('authorization_code')->newAuthorizeRequest('user', 1, $authParams);

        $response = new Response('', 302, [
            'Location'  =>  $redirectUri
        ]);

        return $response;
    }

    // The user denied the request so redirect back with a message
    else {

        $error = new \League\OAuth2\Server\Util\AccessDeniedException;

        $redirectUri = new \League\OAuth2\Server\Util\RedirectUri(
            $authParams['redirect_uri'],
            [
                'error' =>  $error->errorType,
                'message'   =>  $error->getMessage()
            ]
        );

        $response = new Response('', 302, [
            'Location'  =>  $redirectUri
        ]);

        return $response;
    }
});
~~~

The user will be redirected back to the client with either an error message or an authorization code.

If the client recieves an authorization code it will request to turn it into an access token. For this you need an `/access_token` endpoint.

~~~ php
$router->post('/access_token', function (Request $request) use ($server) {

    try {

        $response = $server->issueAccessToken();
        return new Response(
            json_encode($response),
            200
            [
                'Content-type'  =>  'application/json',
                'Cache-Control' =>  'no-store',
                'Pragma'        =>  'no-store'
            ]
        );

    } catch (\Exception $e) {

        return new Response(
            json_encode([
                'error'     =>  $e->errorType,
                'message'   =>  $e->getMessage()
            ]),
            $e->httpStatusCode,
            $e->getHttpHeaders()
        );

    }

});
~~~

### Notes

* You could combine the sign-in form and authorize form into one form
