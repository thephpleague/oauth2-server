---
layout: default
title: Installation
permalink: /installation/
---

# Installation

The recommended installation method is using [Composer](https://getcomposer.org).

The following versions of PHP are supported:

* PHP 5.5 (>=5.5.9)
* PHP 5.6
* PHP 7.0
* HHVM

In your project root just run:

{% highlight shell %}
$ composer require league/oauth2-server
{% endhighlight %}

Ensure that you’ve set up your project to [autoload Composer-installed packages](https://getcomposer.org/doc/00-intro.md#autoloading).

Depending on [which grant]() you are implementing you will need to implement a number of repository interfaces. Each grant documentation page lists which repositories are required, and each repository interface has it's own documentation page. 

The repositories are expected to return (on success) instances of [entity interfaces](https://github.com/thephpleague/oauth2-server/tree/V5-WIP/src/Entities/Interfaces); to make integration with your existing entities and models as easy as possible though, all required methods have been implemented as traits that you can use.