---
layout: default
title: Authorization server events
permalink: /authorization-server/events/
---

# Authorization server events

During the lifecycle of a request passing through the authorization server a number of events are emitted.

You can subscribe to these events by attaching listeners to the authorization server.

## error.auth.client

~~~ php
$server->addEventListener('error.auth.client', function ($event) { });
~~~

This event is emitted when a client fails to authenticate. You might wish to listen to this event in order to ban clients that fail to authenticate after `n` number of attempts.

You can retrieve the request object that was used by calling `getRequest()` on the event object passed into your callable.

## error.auth.user

~~~ php
$server->addEventListener('error.auth.user', function ($event) { });
~~~

This event is emitted when a user fails to authenticate. You might wish to listen to this event in order to reset passwords or ban users that fail to authenticate after `n` number of attempts.

You can retrieve the request object that was used by calling `getRequest()` on the event object passed into your callable.

## session.owner

~~~ php
$server->addEventListener('session.owner', function ($event) { });
~~~

This event is emitted when a session has been allocated an owner (for example a user or a client).

You might want to use this event to dynamically associate scopes to the session depending on the users role or ACL permissions.

You can access the session entity objected by calling `getSession()` on the event object passed into your callable.
