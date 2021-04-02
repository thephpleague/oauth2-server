---
布局：默认
标题：隐式授予
永久链接：/authorization-server/implicit-grant/
---

# 隐式授予

__这种方式已不再是最佳实践__. 文档仅仅是记录下这种授权方式. 业界最佳实践建议，对于本机和基于浏览器的应用程序，不使用客户密码的情况下使用授权代码授予。

隐式授权类似于授权码授权，但有两个明显的区别。

它旨在用于基于用户代理的客户端（例如单页Web应用程序），由于所有应用程序代码和存储都易于访问，因此无法将客户端保密。

其次，代替授权服务器返回被交换访问令牌的授权代码，授权服务器返回访问令牌。

## 流程

客户端将使用查询字符串中的以下参数将用户重定向到授权服务器：

* `response_type` 的值为 `token`
* `client_id` 带有客户端标识符
* `redirect_uri` 户端重定向URI。此参数是可选的，但是如果不发送，则用户将被重定向到预注册的重定向URI
* `scope` 用空格分隔的范围列表
* `state` with a [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) token。此参数是可选的，但强烈建议使用。您应该将CSRF令牌的值存储在用户会话中，以便他们返回时进行验证。

所有这些参数将由授权服务器验证。

然后将要求用户登录授权服务器并批准客户端。

如果用户批准了客户端，则将使用查询字符串中的以下参数将其重定向回授权服务器:

* `token_type` 值为 `Bearer`
* `expires_in` 代表访问令牌的TTL，用整数表示
* `access_token` 用授权服务器的私钥签名的JWT
* `state` 带有在原始请求中发送的state参数。您应该将此值与用户会话中存储的值进行比较，以确保获得的授权码是响应此客户端而不是另一个客户端应用程序发出的请求的。

****Note**** 该授权**不会**返回一个 `refresh token`.

## Setup

无论在何处初始化对象，都将初始化授权服务器的新实例，并绑定存储接口和授权代码授权：

~~~ php
// Init our repositories
$clientRepository = new ClientRepository(); // instance of ClientRepositoryInterface
$scopeRepository = new ScopeRepository(); // instance of ScopeRepositoryInterface
$accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface
$authCodeRepository = new AuthCodeRepository(); // instance of AuthCodeRepositoryInterface

$privateKey = 'file://path/to/private.key';
//$privateKey = new CryptKey('file://path/to/private.key', 'passphrase'); // if private key has a pass phrase
$encryptionKey = 'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen'; // generate using base64_encode(random_bytes(32))

// Setup the authorization server
$server = new \League\OAuth2\Server\AuthorizationServer(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKey,
    $encryptionKey
);

// Enable the implicit grant on the server
$server->enableGrantType(
    new ImplicitGrant(new \DateInterval('PT1H')),
    new \DateInterval('PT1H') // access tokens will expire after 1 hour
);
~~~

## 示例

请注意：这里的这些示例演示了Slim框架的用法；Slim不是使用这个库的要求，您只需要生成与PSR7兼容的HTTP请求和响应的东西就可以_._

The client will redirect the user to an authorization endpoint.

~~~ php
$app->get('/authorize', function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {

    /* @var \League\OAuth2\Server\AuthorizationServer $server */
    $server = $app->getContainer()->get(AuthorizationServer::class);

    try {

        // Validate the HTTP request and return an AuthorizationRequest object.
        $authRequest = $server->validateAuthorizationRequest($request);
        
        // The auth request object can be serialized and saved into a user's session.
        // You will probably want to redirect the user at this point to a login endpoint.
        
        // Once the user has logged in set the user on the AuthorizationRequest
        $authRequest->setUser(new UserEntity()); // an instance of UserEntityInterface
         
        // At this point you should redirect the user to an authorization page.
        // This form will ask the user to approve the client and the scopes requested.
        
        // Once the user has approved or denied the client update the status
        // (true = approved, false = denied)
        $authRequest->setAuthorizationApproved(true);
        
        // Return the HTTP redirect response
        return $server->completeAuthorizationRequest($authRequest, $response);
        
    } catch (OAuthServerException $exception) {
        
        // All instances of OAuthServerException can be formatted into a HTTP response
        return $exception->generateHttpResponse($response);
        
    } catch (\Exception $exception) {
        
        // Unknown exception
        $body = new Stream('php://temp', 'r+');
        $body->write($exception->getMessage());
        return $response->withStatus(500)->withBody($body);
        
    }
});
~~~
