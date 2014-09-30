---
layout: default
title: Securing your API
permalink: /resource-server/securing-your-api/
---

# Securing your API

## Setup

Wherever you intialise your objects, initialize a new instance of the resource server with the storage interfaces:

~~~ php
$sessionStorage = new Storage\SessionStorage();
$accessTokenStorage = new Storage\AccessTokenStorage();
$clientStorage = new Storage\ClientStorage();
$scopeStorage = new Storage\ScopeStorage();

$server = new ResourceServer(
    $sessionStorage,
    $accessTokenStorage,
    $clientStorage,
    $scopeStorage
);
~~~


## Implementation

##  Checking for valid access tokens

Before your API responds you need to check that an access token has been presented with the request (either in the query string `?access_token=abcdef` or as an authorization header `Authorization: Bearer abcdef`).

If you’re using a framework such as Laravel or Symfony you could use a route filter to do this. With the Slim framework you would use middleware.

This example uses Orno\Route:

~~~ php
try {

    // Check that an access token is present and is valid
    $server->isValidRequest();

    // A successful response
    $response = $dispatcher->dispatch(
        $request->getMethod(),
        $request->getPathInfo()
    );

} catch (\League\OAuth2\Server\Exception\OAuthException $e) {

    // Catch an OAuth exception
    $response = new Response(json_encode([
        'error'     =>  $e->errorType,
        'message'   =>  $e->getMessage()
    ]), $e->httpStatusCode);

    foreach ($e->getHttpHeaders() as $header) {
        $response->headers($header);
    }

} catch (\Orno\Http\Exception $e) {

       // A failed response (thrown by code)
       $response = $e->getJsonResponse();
       $response->setContent(json_encode(['status_code' => $e->getStatusCode(), 'message' => $e->getMessage()]));

} catch (\Exception $e) {

    // Other server error (500)
    $response = new Orno\Http\Response;
    $response->setStatusCode(500);
    $response->setContent(json_encode(['status_code' => 500, 'message' => $e->getMessage()]));

} finally {

    // Return the response
    $response->headers->set('Content-type', 'application/json');
    $response->send();

}
~~~

When `$server->isValidRequest()` is called the library will run the following tasks:

* Check if an access token is present in the query string
    * If not, check if an access token is contained in an `authorization` header.
        * If not, throw League\OAuth2\Server\Exception\InvalidAccessTokenException`
* Check if the access token is valid with the database
    * If not, throw `League\OAuth2\Server\Exception\AccessDeniedException`
* If the access token is valid:
    * Get the token's owner type (e.g. “user” or “client”) and their ID
    * Get a list of any scopes that are associated with the access token

Assuming an exception isn’t thrown you can then use the following functions in your API code:

* `getOwnerType()` - This will return the type of the owner of the access token. For example if a user has authorized another client to use their resources the owner type would be “user”.
* `getOwnerId()` - This will return the ID of the access token owner. You can use this to check if the owner has permission to do take some sort of action (such as retrieve a document or upload a file to a folder).
* `getClientId()` - Returns the ID of the client that was involved in creating the session that the access token is linked to.
* `getAccessToken()` - Returns the access token used in the request.
* `hasScope()` - You can use this function to see if a specific scope (or several scopes) has been associated with the access token. You can use this to limit the contents of an API response or prevent access to an API endpoint without the correct scope.
* `getScopes()` - Returns all scopes attached to the access token.

## A simple example

This example endpoint will return a user’s information if a valid access token is present. If the access token has the `email` scope then the user's email address will be included in the response. Likewise if the `photo` scope is available the user's photo is included.

~~~ php
$router->get('/users/{username}', function (Request $request, $args) use ($server) {

    $result = (new Model\Users())->get($args['username']);

    if (count($result) === 0) {
        throw new NotFoundException();
    }

    $user = [
        'username'  =>  $result[0]['username'],
        'name'      =>  $result[0]['name']
    ];

    if ($server->hasScope('email')) {
        $user['email'] = $result[0]['email'];
    }

    if ($server->hasScope('photo')) {
        $user['photo'] = $result[0]['photo'];
    }

    return new Response(json_encode($user));
});
~~~

## Limiting an endpoint to a specific owner type

In this example, only a user’s access token is valid:

~~~ php
if ($server->getOwnerType() !== 'user') {
    throw new Exception\AccessDeniedException;
}
~~~

## Limiting an endpoint to a specific owner type and scope

In this example, the endpoint will only respond to access tokens that are owner by client applications and that have the scope `users.list`.

~~~ php
if ($server->getOwnerType() !== 'client' && $server->hasScope('users.list')) {
    throw new Exception\AccessDeniedException;
}
~~~

You might secure an endpoint in this way to only allow specific clients (such as your applications’ main website) access to private APIs.

## Return resource based on access token owner

~~~ php
$photos = $model->getPhotos($server->getOwnerId());
~~~


Hopefully you can see how easy it is to secure an API with OAuth 2.0 and how you can use scopes to limit response contents or access to endpoints.