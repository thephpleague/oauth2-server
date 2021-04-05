---
布局：默认
标题：资源所有者密码凭据授予
永久链接: /authorization-server/resource-owner-password-credentials-grant/
---

# 资源所有者密码凭据授予

对于Web和本机应用程序中的<u>受信任的</u>第一方客户端，此赠款都是很好的用户体验

## 流程

客户端将要求用户提供其授权凭证（通常是用户名和密码）

然后，客户端将带有以下主体参数的POST请求发送到授权服务器：

* `grant_type` 的值为 `password`
* `client_id` 客户端ID 
* `client_secret` 客户端
* `scope` 以空格分隔的请求范围权限列表
* `username` 用户名
* `password` 用户密码

授权服务器将使用包含以下属性的JSON对象进行响应：

* `token_type` 值为 `Bearer`
* `expires_in` 代表访问令牌的TTL，用整数表示
* `access_token` 用授权服务器的私钥签名的JWT
* `refresh_token` 加密的有效字符串，可用于在过期时刷新访问令牌。

## 使用说明

无论在何处初始化对象，都将初始化授权服务器的新实例，并绑定存储接口和授权代码授权:

~~~ php
// Init our repositories
$clientRepository = new ClientRepository(); // instance of ClientRepositoryInterface
$scopeRepository = new ScopeRepository(); // instance of ScopeRepositoryInterface
$accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface
$userRepository = new UserRepository(); // instance of UserRepositoryInterface
$refreshTokenRepository = new RefreshTokenRepository(); // instance of RefreshTokenRepositoryInterface

// 公钥和私钥的路径
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

$grant = new \League\OAuth2\Server\Grant\PasswordGrant(
     $userRepository,
     $refreshTokenRepository
);

$grant->setRefreshTokenTTL(new \DateInterval('P1M')); // refresh tokens will expire after 1 month

// Enable the password grant on the server
$server->enableGrantType(
    $grant,
    new \DateInterval('PT1H') // access tokens will expire after 1 hour
);
~~~

## 示例

请注意：这里的这些示例演示了Slim框架的用法；Slim不是使用这个库的要求，您只需要生成与PSR7兼容的HTTP请求和响应的东西就可以_._

客户端将请求访问令牌，因此创建一个`/access_token`端点。

~~~ php
$app->post('/access_token', function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {

    /* @var \League\OAuth2\Server\AuthorizationServer $server */
    $server = $app->getContainer()->get(AuthorizationServer::class);

    try {
    
        // Try to respond to the request
        return $server->respondToAccessTokenRequest($request, $response);
        
    } catch (\League\OAuth2\Server\Exception\OAuthServerException $exception) {
    
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
