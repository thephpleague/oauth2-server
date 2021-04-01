---
布局：默认
标题：授权码授予
永久链接：/authorization-server/auth-code-grant/
---

# 授权码授予

如果您曾经使用Facebook或Google帐户登录过网络应用程序，则授权码授予应该非常熟悉。

## 流程

### 第一部分

客户端将使用查询字符串中的以下参数将用户重定向到授权服务器：

* `response_type` 的值为 `code`
* `client_id` 带有客户端标识符
* `redirect_uri` 客户端重定向URI。此参数是可选的，但是如果不发送，则用户将被重定向到预注册的重定向URI
* `scope`  用空格分隔的范围列表
* 带有[CSRF]（https://en.wikipedia.org/wiki/Cross-site_request_forgery）令牌的`state`。此参数是可选的，但强烈建议使用。您应该将CSRF令牌的值存储在用户会话中，以便他们返回时进行验证。

所有这些参数将由授权服务器验证。

然后将要求用户登录授权服务器并批准客户端。

如果用户批准了客户端，则将使用查询字符串中的以下参数将它们从授权服务器重定向到客户端的重定向URI：

* `code` 和授权码
* `state` 带有在原始请求中发送的state参数。您应该将此值与用户会话中存储的值进行比较，以确保获得的授权码是响应此客户端而不是另一个客户端应用程序发出的请求的。

### 第二部分

客户端现在将使用以下参数将POST请求发送到授权服务器：

* 值为 `authorization_code`的`grant_type` 
* `client_id` 客户端标识符
* `client_secret` 客户端密钥
* `redirect_uri` 用户重定向url相同的链接
* `code` 带有查询字符串中的授权码

请注意，您需要先对`code`查询字符串进行解码。你可以用`urldecode($code)`来做到这一点。

授权服务器将使用包含以下属性的JSON对象进行响应： 

* `token_type` 值是 `Bearer`
* `expires_in` 其整数表示访问令牌的TTL
* `access_token` 用授权服务器的私钥签名的JWT
* `refresh_token` 加密的有效字符串，可用于在过期时刷新访问令牌。

## 使用说明

无论在何处初始化对象，都将初始化授权服务器的新实例，并绑定存储接口和授权代码授权：

~~~ php
// 初始化仓库
$clientRepository = new ClientRepository(); // instance of ClientRepositoryInterface
$scopeRepository = new ScopeRepository(); // instance of ScopeRepositoryInterface
$accessTokenRepository = new AccessTokenRepository(); // instance of AccessTokenRepositoryInterface
$authCodeRepository = new AuthCodeRepository(); // instance of AuthCodeRepositoryInterface
$refreshTokenRepository = new RefreshTokenRepository(); // instance of RefreshTokenRepositoryInterface

$privateKey = 'file://path/to/private.key';
//$privateKey = new CryptKey('file://path/to/private.key', 'passphrase'); // 如果私钥有密码短语
$encryptionKey = 'lxZFUEsBCJ2Yb14IF2ygAHI5N4+ZAUXXaSeeJm6+twsUmIen'; // generate using base64_encode(random_bytes(32))

// 设置授权服务器
$server = new \League\OAuth2\Server\AuthorizationServer(
    $clientRepository,
    $accessTokenRepository,
    $scopeRepository,
    $privateKey,
    $encryptionKey
);

$grant = new \League\OAuth2\Server\Grant\AuthCodeGrant(
     $authCodeRepository,
     $refreshTokenRepository,
     new \DateInterval('PT10M') // 授权代码将在10分钟后过期
 );

$grant->setRefreshTokenTTL(new \DateInterval('P1M')); // 刷新令牌将在1个月后过期

// 在服务器上启用身份验证代码授予
$server->enableGrantType(
    $grant,
    new \DateInterval('PT1H') //访问令牌将在1小时后过期
);
~~~

## 样例

请注意：这里的这些示例演示了Slim框架的用法；Slim不是使用这个库的要求，您只需要生成与PSR7兼容的HTTP请求和响应的东西就可以_._

客户端将用户重定向到授权端

~~~ php
$app->get('/authorize', function (ServerRequestInterface $request, ResponseInterface $response) use ($server) {
   
    try {
    
        // 验证HTTP请求并返回AuthorizationRequest对象.
        $authRequest = $server->validateAuthorizationRequest($request);
        
        // 可以将auth请求对象序列化并保存到用户的会话中.
        // 此时，您可能需要将用户重定向到登录端点.
        
        // 一旦用户登录，就在AuthorizationRequest上设置该用户
        $authRequest->setUser(new UserEntity()); // an instance of UserEntityInterface
        
        // 此时，您应该将用户重定向到授权页面。
        // 此表单将要求用户批准客户端和请求的范围。
        
        // 用户批准或拒绝后，客户端将更新状态
        // (true = approved, false = denied)
        $authRequest->setAuthorizationApproved(true);
        
        // 返回HTTP重定向响应
        return $server->completeAuthorizationRequest($authRequest, $response);
        
    } catch (OAuthServerException $exception) {
    
        // 可以将OAuthServerException的所有实例格式化为HTTP响应
        return $exception->generateHttpResponse($response);
        
    } catch (\Exception $exception) {
    
        // Unknown exception
        $body = new Stream(fopen('php://temp', 'r+'));
        $body->write($exception->getMessage());
        return $response->withStatus(500)->withBody($body);
        
    }
});
~~~

客户端将使用授权码请求访问令牌，因此创建`/access_token`端点

~~~ php
$app->post('/access_token', function (ServerRequestInterface $request, ResponseInterface $response) use ($server) {

    try {
    
        // 尝试回应请求
        return $server->respondToAccessTokenRequest($request, $response);

    } catch (\League\OAuth2\Server\Exception\OAuthServerException $exception) {
    
        // 可以将OAuthServerException的所有实例格式化为HTTP响应
        return $exception->generateHttpResponse($response);
        
    } catch (\Exception $exception) {
    
        // Unknown exception
        $body = new Stream(fopen('php://temp', 'r+'));
        $body->write($exception->getMessage());
        return $response->withStatus(500)->withBody($body);
    }
});
~~~

