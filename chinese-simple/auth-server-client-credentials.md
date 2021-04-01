---
布局：默认
标题：客户凭证授予
永久链接：/authorization-server/client-credentials-grant/
---

# 客户凭证授予

该授权适用于机器对机器的身份验证，例如，用于在通过API执行维护任务的cron作业中使用。另一个示例是客户端向不需要用户许可的API发出请求。.

## 流程

客户端将带有以下主体参数的POST请求发送到授权服务器：

* 带有 `client_credentials`的`grant_type` 
* `client_id` 客户端ID
* `client_secret` 客户端密钥
* `scope` 带有以空格分隔的请求范围权限列表

授权服务器将使用包含以下属性的JSON对象进行响应：

* `token_type` 值为 `Bearer`
* `expires_in` 代表访问令牌的TTL，用整数表示
* `access_token` 用授权服务器的私钥签名的JWT

## 使用说明

无论在何处初始化对象，都将初始化授权服务器的新实例，并绑定存储接口和授权代码授权:

~~~ php
// Init our repositories
$clientRepository = new ClientRepository(); // instance of ClientRepositoryInterface
$scopeRepository = new ScopeRepository(); // instance of ScopeRepositoryInterface
$accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface

// Path to public and private keys
$privateKey = 'file://path/to/private.key';
//$privateKey = new CryptKey('file://path/to/private.key', 'passphrase'); // if private key has a pass phrase
$encryptionKey = 'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen'; // generate using base64_encode(random_bytes(32))

// 设置授权服务器
$server = new \League\OAuth2\Server\AuthorizationServer(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKey,
    $encryptionKey
);

//在服务器上启用客户端凭据授予
$server->enableGrantType(
    new \League\OAuth2\Server\Grant\ClientCredentialsGrant(),
    new \DateInterval('PT1H') // 访问令牌将在1小时后过期
);
~~~

## 样例

请注意：这里的这些示例演示了Slim框架的用法；Slim不是使用这个库的要求，您只需要生成与PSR7兼容的HTTP请求和响应的东西就可以_._

客户端将请求访问令牌，因此创建一个`/ access_token`端点

~~~ php
$app->post('/access_token', function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {

    /* @var \League\OAuth2\Server\AuthorizationServer $server */
    $server = $app->getContainer()->get(AuthorizationServer::class);

    try {
    
        // Try to respond to the request
        return $server->respondToAccessTokenRequest($request, $response);
        
    } catch (\League\OAuth2\Server\Exception\OAuthServerException $exception) {
    
        // 可以将OAuthServerException的所有实例格式化为HTTP响应
        return $exception->generateHttpResponse($response);
        
    } catch (\Exception $exception) {
    
        // Unknown exception
        $body = new Stream('php://temp', 'r+');
        $body->write($exception->getMessage());
        return $response->withStatus(500)->withBody($body);
        
    }
});
~~~
