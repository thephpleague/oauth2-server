---
layout: default
title: Upgrade Guide
permalink: /upgrade-guide/
---

# Upgrade Guide

## 5.1.x &rarr; 6.x.x

Version `6.x.x` is not backwards compatible with version `5.1.x` but only requires you to make one line of code change:

```patch
  $server = new AuthorizationServer(
      $clientRepository,
      $accessTokenRepository,
      $scopeRepository,
      $privateKeyPath,
+     'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen'
-      $publicKeyPath
  );
```

All you need to do is replace the public key that was being passed into the constructor of `AuthorizationServer` with a 32 bit encryption key.

To generate an encryption key for the `AuthorizationServer` run the following command in the terminal:

{% highlight shell %}
php -r 'echo base64_encode(random_bytes(32)), PHP_EOL;'
{% endhighlight %}
