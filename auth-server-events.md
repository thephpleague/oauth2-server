---
layout: default
title: Authorization server events
permalink: /authorization-server/events/
---

# Authorization server events

During the lifecycle of a request passing through the authorization server a number of events may be emitted.

You can subscribe to these events by attaching listeners to the authorization server.

To access the emitter call this method:

{% highlight php %}
$server->getEmitter(); // returns instance of \League\Event\EmitterInterface
{% endhighlight %}

## client.authentication.failed

{% highlight php %}
$server->getEmitter()->addListener(
    'client.authentication.failed',
    function (\League\OAuth2\Server\RequestEvent $event) {
        // do something
    }
);
{% endhighlight %}

This event is emitted when a client fails to authenticate. You might wish to listen to this event in order to ban clients that fail to authenticate after `n` number of attempts.

You can retrieve the request object that was used by calling `getRequest()` on the event object passed into your callable.

## user.authentication.failed

{% highlight php %}
$server->getEmitter()->addListener(
    'user.authentication.failed',
    function (\League\OAuth2\Server\RequestEvent $event) {
        // do something
    }
);
{% endhighlight %}

This event is emitted when a user fails to authenticate. You might wish to listen to this event in order to reset passwords or ban users that fail to authenticate after `n` number of attempts.

You can retrieve the request object that was used by calling `getRequest()` on the event object passed into your callable.