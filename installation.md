---
layout: default
title: Installation
permalink: /installation/
---

# Installation

The recommended way of installing the library is via Composer.

If you already have a composer.json file in your root then add `"league/oauth2-server": "4.*"` in the require object. Then run `composer update`.

Otherwise create a new file in your project root called composer.json add set the contents to:

~~~ javascript
{
    "require": {
        "league/oauth2-server": "4.0.*@dev"
    }
}
~~~

Now, assuming you have [installed Composer](https://getcomposer.org/download/) run `composer update`.

Ensure now that you’ve set up your project to [autoload Composer-installed packages](https://getcomposer.org/doc/00-intro.md#autoloading).
