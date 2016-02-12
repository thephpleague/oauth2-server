<?php

use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Server;
use OAuth2ServerExamples\Repositories\AccessTokenRepository;
use OAuth2ServerExamples\Repositories\ClientRepository;
use OAuth2ServerExamples\Repositories\ScopeRepository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\App;
use Zend\Diactoros\Stream;

include(__DIR__ . '/../vendor/autoload.php');

$app = new App([
    'settings'    => [
        'displayErrorDetails' => true,
    ],
    Server::class => function () {
        // Init our repositories
        $clientRepository = new ClientRepository();
        $accessTokenRepository = new AccessTokenRepository();
        $scopeRepository = new ScopeRepository();

        $privateKeyPath = 'file://' . __DIR__ . '/../private.key';
        $publicKeyPath = 'file://' . __DIR__ . '/../public.key';

        // Setup the authorization server
        return new Server(
            $clientRepository,
            $accessTokenRepository,
            $scopeRepository,
            $privateKeyPath,
            $publicKeyPath
        );
    }
]);

$app->get('/user', function (ServerRequestInterface $request, ResponseInterface $response) use ($app) {
    $server = $app->getContainer()->get(Server::class);
    $body = new Stream('php://temp', 'r+');

    try {
        $request = $server->validateRequest($request);
    } catch (OAuthServerException $exception) {
        return $exception->generateHttpResponse($response);
    } catch (\Exception $exception) {
        $body->write($exception->getMessage());

        return $response->withStatus(500)->withBody($body);
    }

    $params = [];

    if (in_array('basic', $request->getAttribute('oauth_scopes', []))) {
        $params = [
            'id'   => 1,
            'name' => 'Alex',
            'city' => 'London'
        ];
    }

    if (in_array('email', $request->getAttribute('oauth_scopes', []))) {
        $params['email'] = 'alex@example.com';
    }

    $body->write(json_encode($params));

    return $response->withBody($body);
});

$app->run();
