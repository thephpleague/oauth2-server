---
layout: default
title: 刷新令牌授予
permalink: /authorization-server/refresh-token-grant/
---

# 刷新令牌授予

访问令牌最终会过期； 但是，某些授予使用刷新令牌进行响应，该刷新令牌使客户端可以刷新访问令牌。

## 流程

* 客户端将带有以下主体参数的POST请求发送到授权服务器：

* 带有 `refresh_token`的`grant_type` 
* `refresh_token` 刷新token
* `client_id` 客户端ID
* `client_secret` 客户端密钥
* `scope` 以空格分隔的请求范围权限列表。这是可选的；如果未发送，则将使用原始范围，否则，您可以请求缩小的范围集。

授权服务器将使用包含以下属性的JSON对象进行响应：

* `token_type` 值为 `Bearer`
* `expires_in` 代表访问令牌的TTL，用整数表示
* `access_token` 使用授权服务器的私钥签名的新JWT
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
​~~~:
~~~

~~~ php
// Init our repositories
$clientRepository = new ClientRepository();
$accessTokenRepository = new AccessTokenRepository();
$scopeRepository = new ScopeRepository();
$refreshTokenRepository = new RefreshTokenRepository();

// Path to public and private keys
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

$grant = new \League\OAuth2\Server\Grant\RefreshTokenGrant($refreshTokenRepository);
$grant->setRefreshTokenTTL(new \DateInterval('P1M')); // new refresh tokens will expire after 1 month

// Enable the refresh token grant on the server
$server->enableGrantType(
    $grant,
    new \DateInterval('PT1H') // new access tokens will expire after an hour
);
~~~

## 示例

客户端将请求一个访问令牌，以便创建一个 `/access_token` 端点.

~~~ php
$app->post('/access_token', function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {

    /* @var \League\OAuth2\Server\AuthorizationServer $server */
    $server = $app->getContainer()->get(AuthorizationServer::class);

    // Try to respond to the request
    try {
        return $server->respondToAccessTokenRequest($request, $response);

    } catch (\League\OAuth2\Server\Exception\OAuthServerException $exception) {
        return $exception->generateHttpResponse($response);

    } catch (\Exception $exception) {
        $body = new Stream('php://temp', 'r+');
        $body->write($exception->getMessage());
        return $response->withStatus(500)->withBody($body);
    }
});
~~~
