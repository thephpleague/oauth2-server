---
布局：默认
标题：授权服务器事件
永久链接：/authorization-server/events/
---

# 授权服务器事件

在通过授权服务器的请求的生命周期中，可能会发出许多事件。

您可以通过将侦听器附加到授权服务器来订阅这些事件。

要访问发射器，请调用此方法：

~~~ php
$server->getEmitter(); // returns instance of \League\Event\EmitterInterface
~~~

## client.authentication.failed

~~~ php
$server->getEmitter()->addListener(
    'client.authentication.failed',
    function (\League\OAuth2\Server\RequestEvent $event) {
        // do something
    }
);
~~~

客户端身份验证失败时，将发出此事件。您可能希望侦听此事件，以禁止在`n`次尝试后未能通过身份验证的客户端。

您可以通过传递给可调用对象的事件对象上的调用`getRequest()`来检索所使用的请求对象。

## user.authentication.failed

~~~ php
$server->getEmitter()->addListener(
    'user.authentication.failed',
    function (\League\OAuth2\Server\RequestEvent $event) {
        // do something
    }
);
~~~

用户验证失败时，将发出此事件。您可能希望侦听此事件，以重置密码或禁止在`n`次尝试后无法通过身份验证的用户。

您可以通过传递给可调用对象的事件对象上的调用`getRequest()`来检索所使用的请求对象。